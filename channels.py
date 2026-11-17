"""
Topic channels. A channel is a Group (kind='channel') so messaging, encryption,
calls and read receipts stay on the existing tables.

Permission decisions are pure functions so tests do not need Postgres.
"""

import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database_models import Group, GroupMember, GroupMessageRead, HiddenMessage, Message, ThreadFollow, User
from org_privileges import has_org_privilege, is_org_account

_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    slug = _SLUG.sub("-", (name or "").strip().lower()).strip("-")[:80]
    return slug or "channel"


def is_group_admin_role(role) -> bool:
    """Channel owners run the group the same way an admin does."""
    return role in ("admin", "owner")


def is_org_channel_admin(user) -> bool:
    """Site admin, the organization account, or a member granted manage_groups.

    Portal viewers are read-only. They are not implicit admins.
    """
    return bool(
        getattr(user, "is_admin", False)
        or is_org_account(user)
        or has_org_privilege(user, "manage_groups")
    )


def same_org(user, organization_id) -> bool:
    if getattr(user, "is_admin", False):
        return True
    return organization_id is not None and getattr(user, "organization_id", None) == organization_id


def posting_block(role: Optional[str], posting_policy: str, archived: bool, org_admin: bool) -> Optional[str]:
    """None when the caller may post. Archived wins over the admin exception."""
    if archived:
        return "This channel is archived"
    if posting_policy == "admins" and role not in ("owner", "admin") and not org_admin:
        return "Only channel admins can post here"
    return None


def can_manage(role: Optional[str], org_admin: bool) -> bool:
    return org_admin or role in ("owner", "admin")


def member_change_block(actor_role: Optional[str], target_role: str, org_admin: bool, action: str) -> Optional[str]:
    """Admins may add or remove members. Only the owner changes an admin."""
    if target_role == "owner":
        return "Transfer ownership before changing the owner"
    if action == "promote" and actor_role != "owner" and not org_admin:
        return "Only the owner can promote a channel admin"
    if target_role == "admin" and actor_role != "owner" and not org_admin:
        return "Only the owner can change a channel admin"
    return None


def group_write_uses_channel_api(kind: Optional[str]) -> bool:
    """Old /groups writes must not change a channel."""
    return kind == "channel"


def in_channel_timeline(kind: Optional[str], thread_root_id) -> bool:
    """Thread replies stay in the thread panel. Groups have no threads."""
    return not (kind == "channel" and thread_root_id is not None)


def can_join(visibility: str, already_member: bool, archived: bool = False) -> Optional[str]:
    if archived:
        return "This channel is archived"
    if already_member:
        return "Already a member"
    if visibility != "public":
        return "Private channels are invite-only"
    return None


def can_leave(role: Optional[str]) -> Optional[str]:
    if role is None:
        return "You are not a member of this channel"
    if role == "owner":
        return "Transfer ownership before leaving"
    return None


def thread_push_recipients(follower_ids, author_id, sender_id, muted_ids, mentioned_ids=None) -> list:
    """Followers, the root author, and mentioned members, except the sender and muted chats."""
    ids = set(follower_ids or [])
    if author_id:
        ids.add(int(author_id))
    for mentioned in mentioned_ids or []:
        ids.add(int(mentioned))
    ids.discard(int(sender_id))
    muted = set(muted_ids or [])
    return sorted(uid for uid in ids if uid not in muted)


def prepare_thread_root(db: Session, group, thread_root_id):
    """Resolve a thread root before any message is inserted.

    Returns the root row, or None when this send is not a reply. A bad id
    raises so the caller never stores a timeline message by mistake.
    """
    if not thread_root_id:
        return None
    if group is None or getattr(group, "kind", None) != "channel":
        raise HTTPException(status_code=400, detail="Threads are only available in channels")
    root = db.query(Message).filter(
        Message.id == int(thread_root_id),
        Message.group_id == int(group.id),
    ).first()
    if not root or root.thread_root_id is not None:
        raise HTTPException(status_code=404, detail="Thread not found")
    return root


def reply_target_block(target_group_id, group_id) -> Optional[str]:
    if target_group_id is None or int(target_group_id) != int(group_id):
        return "Reply target is not in this conversation"
    return None


def apply_thread_reply(db: Session, root_id: int, when: Optional[datetime] = None) -> None:
    """Atomic increment so two replies at once cannot lose a count."""
    when = when or datetime.now(timezone.utc)
    db.query(Message).filter(Message.id == root_id).update(
        {
            Message.thread_reply_count: func.coalesce(Message.thread_reply_count, 0) + 1,
            Message.thread_last_reply_at: when,
        },
        synchronize_session="fetch",
    )


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    topic: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = None
    visibility: str = "private"
    posting_policy: str = "everyone"
    members: list[str] = []


class ChannelPatch(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    topic: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = None
    visibility: Optional[str] = None
    posting_policy: Optional[str] = None


class ChannelMessageIn(BaseModel):
    message: str = Field(..., min_length=1)
    encrypted_key: Optional[str] = None
    iv: Optional[str] = None
    decoy_content: Optional[str] = None
    content_type: Optional[str] = None
    thread_root_id: Optional[int] = None
    reply_to_message_id: Optional[int] = None
    mentions: Optional[list[str]] = None


class MemberIn(BaseModel):
    username: str


class TransferIn(BaseModel):
    username: str


def _role(db: Session, channel_id: int, user_id: int) -> Optional[str]:
    row = db.query(GroupMember).filter(
        GroupMember.group_id == channel_id, GroupMember.user_id == user_id
    ).first()
    return row.role if row else None


def _channel(db: Session, channel_id: int) -> Group:
    row = db.query(Group).filter(Group.id == channel_id).first()
    if not row or getattr(row, "kind", "group") != "channel":
        raise HTTPException(status_code=404, detail="Channel not found")
    return row


def _require_reader(db: Session, channel: Group, user) -> Optional[str]:
    role = _role(db, int(channel.id), int(user.id))
    org_admin = is_org_channel_admin(user) and same_org(user, channel.organization_id)
    if role is None and not org_admin:
        raise HTTPException(status_code=403, detail="You are not a member of this channel")
    return role


def _require_manager(db: Session, channel: Group, user) -> str:
    role = _require_reader(db, channel, user)
    if not can_manage(role, is_org_channel_admin(user) and same_org(user, channel.organization_id)):
        raise HTTPException(status_code=403, detail="Only channel owners and admins can do this")
    return role or "admin"


def _channel_stats(db: Session, channel_ids: list, viewer_id: Optional[int]):
    """Member and unread counts for a page of channels, one query each."""
    if not channel_ids:
        return {}, {}, {}
    members = dict(
        db.query(GroupMember.group_id, func.count(GroupMember.id))
        .filter(GroupMember.group_id.in_(channel_ids))
        .group_by(GroupMember.group_id)
        .all()
    )
    roles = {}
    unread = {}
    if viewer_id:
        roles = dict(
            db.query(GroupMember.group_id, GroupMember.role)
            .filter(GroupMember.user_id == viewer_id, GroupMember.group_id.in_(channel_ids))
            .all()
        )
        read_ids = db.query(GroupMessageRead.message_id).filter(GroupMessageRead.user_id == viewer_id)
        unread = dict(
            db.query(Message.group_id, func.count(Message.id))
            .filter(
                Message.group_id.in_(channel_ids),
                Message.sender_id != viewer_id,
                Message.thread_root_id.is_(None),
                Message.is_deleted.is_(False),
                ~Message.id.in_(read_ids),
            )
            .group_by(Message.group_id)
            .all()
        )
    return members, unread, roles


def channel_dict(db: Session, channel: Group, viewer_id: Optional[int], stats=None) -> dict:
    if stats is None:
        members, unread, roles = _channel_stats(db, [int(channel.id)], viewer_id)
    else:
        members, unread, roles = stats
    return {
        "id": int(channel.id),
        "name": channel.name,
        "slug": channel.slug,
        "topic": channel.topic,
        "description": channel.description,
        "visibility": channel.visibility,
        "posting_policy": channel.posting_policy,
        "is_archived": bool(channel.is_archived),
        "organization_id": channel.organization_id,
        "created_by": int(channel.created_by),
        "member_count": int(members.get(channel.id, 0)),
        "my_role": roles.get(channel.id),
        "unread_count": int(unread.get(channel.id, 0)),
        "kind": "channel",
    }


def channel_dicts(db: Session, channels: list, viewer_id: Optional[int]) -> list:
    stats = _channel_stats(db, [int(channel.id) for channel in channels], viewer_id)
    return [channel_dict(db, channel, viewer_id, stats) for channel in channels]


def _unique_slug(db: Session, organization_id: int, name: str, ignore_id: Optional[int] = None) -> str:
    base = slugify(name)
    slug = base
    n = 2
    while True:
        taken = db.query(Group).filter(
            Group.organization_id == organization_id,
            Group.kind == "channel",
            Group.slug == slug,
        ).first()
        if not taken or (ignore_id is not None and int(taken.id) == int(ignore_id)):
            return slug
        slug = f"{base[:76]}-{n}"
        n += 1


def _user_in_org(db: Session, username: str, organization_id: int) -> User:
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user or user.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def install_channel_routes(app: FastAPI, get_current_user, get_database_session, audit, notify, deliver):
    """audit(db, user_id, event, description). notify is awaited with (user_ids, payload).
    deliver(db, user, group_id, fields) is the group send path. Channels do not insert messages themselves.
    """

    @app.post("/channels", status_code=201)
    async def create_channel(
        body: ChannelCreate,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        org_id = getattr(current_user, "organization_id", None)
        if not org_id:
            raise HTTPException(status_code=403, detail="An organization membership is required")
        if body.visibility not in ("public", "private"):
            raise HTTPException(status_code=400, detail="visibility must be public or private")
        if body.posting_policy not in ("everyone", "admins"):
            raise HTTPException(status_code=400, detail="posting_policy must be everyone or admins")
        channel = None
        notified = [int(current_user.id)]
        for _attempt in range(5):
            slug = _unique_slug(db, org_id, body.name)
            channel = Group(
                name=body.name.strip(),
                description=(body.description or "").strip() or None,
                topic=(body.topic or "").strip() or None,
                created_by=int(current_user.id),
                kind="channel",
                visibility=body.visibility,
                organization_id=org_id,
                posting_policy=body.posting_policy,
                slug=slug,
                is_archived=False,
            )
            db.add(channel)
            try:
                db.flush()
                db.add(GroupMember(group_id=channel.id, user_id=int(current_user.id), role="owner"))
                notified = [int(current_user.id)]
                for username in body.members:
                    member = _user_in_org(db, username, org_id)
                    if member.id == current_user.id:
                        continue
                    db.add(GroupMember(group_id=channel.id, user_id=member.id, role="member"))
                    notified.append(int(member.id))
                db.commit()
                break
            except IntegrityError:
                db.rollback()
                channel = None
        if channel is None or getattr(channel, "id", None) is None:
            raise HTTPException(status_code=409, detail="Could not reserve a channel name")
        db.refresh(channel)
        audit(db, int(current_user.id), "channel_created", f"Channel {channel.id} created")
        await notify(notified, {"type": "channel_updated", "data": {"channel_id": int(channel.id), "event": "created"}})
        return channel_dict(db, channel, int(current_user.id))

    @app.get("/channels/browse")
    async def browse_channels(
        q: str = Query("", max_length=100),
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        org_id = getattr(current_user, "organization_id", None)
        if not org_id and not getattr(current_user, "is_admin", False):
            return []
        joined = {
            row.group_id for row in db.query(GroupMember.group_id).filter(GroupMember.user_id == int(current_user.id)).all()
        }
        query = db.query(Group).filter(Group.kind == "channel", Group.visibility == "public", Group.is_archived.is_(False))
        if org_id:
            query = query.filter(Group.organization_id == org_id)
        term = q.strip().lower()
        rows = []
        for channel in query.all():
            if channel.id in joined:
                continue
            hay = " ".join(filter(None, [channel.name, channel.topic, channel.description])).lower()
            if term and term not in hay:
                continue
            rows.append(channel)
        return channel_dicts(db, rows, int(current_user.id))

    @app.get("/channels")
    async def list_channels(
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        user_id = int(current_user.id)
        joined_ids = {
            row.group_id for row in db.query(GroupMember.group_id).filter(GroupMember.user_id == user_id).all()
        }
        rows = []
        seen = set()
        if joined_ids:
            for channel in db.query(Group).filter(Group.kind == "channel", Group.id.in_(joined_ids)).all():
                rows.append(channel)
                seen.add(channel.id)
        if is_org_channel_admin(current_user):
            extra = db.query(Group).filter(Group.kind == "channel")
            org_id = getattr(current_user, "organization_id", None)
            if org_id and not getattr(current_user, "is_admin", False):
                extra = extra.filter(Group.organization_id == org_id)
            for channel in extra.all():
                if channel.id not in seen:
                    rows.append(channel)
        return channel_dicts(db, rows, user_id)

    @app.get("/channels/{channel_id}")
    async def get_channel(
        channel_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        _require_reader(db, channel, current_user)
        return channel_dict(db, channel, int(current_user.id))

    @app.post("/channels/{channel_id}/join")
    async def join_channel(
        channel_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        if not same_org(current_user, channel.organization_id):
            raise HTTPException(status_code=404, detail="Channel not found")
        role = _role(db, channel_id, int(current_user.id))
        reason = can_join(channel.visibility, role is not None, bool(channel.is_archived))
        if reason:
            raise HTTPException(status_code=403, detail=reason)
        db.add(GroupMember(group_id=channel_id, user_id=int(current_user.id), role="member"))
        db.commit()
        return channel_dict(db, channel, int(current_user.id))

    @app.post("/channels/{channel_id}/leave")
    async def leave_channel(
        channel_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        role = _role(db, channel_id, int(current_user.id))
        reason = can_leave(role)
        if reason:
            status = 409 if role == "owner" else 403
            raise HTTPException(status_code=status, detail=reason)
        db.query(GroupMember).filter(
            GroupMember.group_id == channel_id, GroupMember.user_id == int(current_user.id)
        ).delete()
        db.commit()
        return {"left": True, "channel_id": channel_id}

    @app.patch("/channels/{channel_id}")
    async def patch_channel(
        channel_id: int,
        body: ChannelPatch,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        saved = False
        for _attempt in range(5):
            channel = _channel(db, channel_id)
            _require_manager(db, channel, current_user)
            if body.name is not None and body.name.strip():
                channel.name = body.name.strip()
                channel.slug = _unique_slug(db, channel.organization_id, channel.name, ignore_id=int(channel.id))
            if body.topic is not None:
                channel.topic = body.topic.strip() or None
            if body.description is not None:
                channel.description = body.description.strip() or None
            if body.visibility is not None:
                if body.visibility not in ("public", "private"):
                    raise HTTPException(status_code=400, detail="visibility must be public or private")
                channel.visibility = body.visibility
            if body.posting_policy is not None:
                if body.posting_policy not in ("everyone", "admins"):
                    raise HTTPException(status_code=400, detail="posting_policy must be everyone or admins")
                channel.posting_policy = body.posting_policy
            try:
                db.commit()
                saved = True
                break
            except IntegrityError:
                db.rollback()
        if not saved:
            raise HTTPException(status_code=409, detail="Could not reserve a channel name")
        audit(db, int(current_user.id), "channel_updated", f"Channel {channel_id} updated")
        return channel_dict(db, channel, int(current_user.id))

    @app.post("/channels/{channel_id}/archive")
    async def archive_channel(
        channel_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return await _set_archived(channel_id, True, current_user, db, audit)

    @app.post("/channels/{channel_id}/unarchive")
    async def unarchive_channel(
        channel_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return await _set_archived(channel_id, False, current_user, db, audit)

    @app.post("/channels/{channel_id}/transfer-ownership")
    async def transfer_ownership(
        channel_id: int,
        body: TransferIn,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        role = _role(db, channel_id, int(current_user.id))
        org_admin = is_org_channel_admin(current_user) and same_org(current_user, channel.organization_id)
        if role != "owner" and not org_admin:
            raise HTTPException(status_code=403, detail="Only the owner can transfer ownership")
        target = _user_in_org(db, body.username, channel.organization_id)
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == channel_id, GroupMember.user_id == target.id
        ).first()
        if not membership:
            raise HTTPException(status_code=404, detail="User is not a member of this channel")
        current = db.query(GroupMember).filter(
            GroupMember.group_id == channel_id, GroupMember.role == "owner"
        ).first()
        if current and current.user_id != target.id:
            current.role = "admin"
        membership.role = "owner"
        db.commit()
        audit(db, int(current_user.id), "channel_ownership_transferred", f"Channel {channel_id} owner is now {body.username}")
        return channel_dict(db, channel, int(current_user.id))

    @app.post("/channels/{channel_id}/members")
    async def invite_member(
        channel_id: int,
        body: MemberIn,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        _require_manager(db, channel, current_user)
        if channel.is_archived:
            raise HTTPException(status_code=403, detail="This channel is archived")
        target = _user_in_org(db, body.username, channel.organization_id)
        existing = db.query(GroupMember).filter(
            GroupMember.group_id == channel_id, GroupMember.user_id == target.id
        ).first()
        if not existing:
            db.add(GroupMember(group_id=channel_id, user_id=target.id, role="member"))
            db.commit()
            audit(db, int(current_user.id), "channel_member_added", f"{body.username} added to channel {channel_id}")
            await notify([int(target.id)], {"type": "channel_updated", "data": {"channel_id": channel_id, "event": "added"}})
        return {"username": body.username, "role": "member"}

    @app.delete("/channels/{channel_id}/members/{username}")
    async def remove_member(
        channel_id: int,
        username: str,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        _require_manager(db, channel, current_user)
        target = _user_in_org(db, username, channel.organization_id)
        membership = db.query(GroupMember).filter(
            GroupMember.group_id == channel_id, GroupMember.user_id == target.id
        ).first()
        if not membership:
            raise HTTPException(status_code=404, detail="User is not a member of this channel")
        if membership.role == "owner":
            raise HTTPException(status_code=403, detail="Transfer ownership before removing the owner")
        actor_role = _role(db, channel_id, int(current_user.id))
        org_admin = is_org_channel_admin(current_user) and same_org(current_user, channel.organization_id)
        blocked = member_change_block(actor_role, membership.role, org_admin, "remove")
        if blocked:
            raise HTTPException(status_code=403, detail=blocked)
        root_ids = db.query(Message.id).filter(Message.group_id == channel_id, Message.thread_root_id.is_(None))
        db.query(ThreadFollow).filter(
            ThreadFollow.user_id == target.id, ThreadFollow.root_message_id.in_(root_ids)
        ).delete(synchronize_session=False)
        db.delete(membership)
        db.commit()
        await notify([int(target.id)], {"type": "channel_updated", "data": {"channel_id": channel_id, "event": "removed"}})
        return {"removed": username}

    @app.post("/channels/{channel_id}/members/{username}/promote")
    async def promote_member(
        channel_id: int, username: str,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return _set_role(db, channel_id, username, "admin", current_user)

    @app.post("/channels/{channel_id}/members/{username}/demote")
    async def demote_member(
        channel_id: int, username: str,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        return _set_role(db, channel_id, username, "member", current_user)

    @app.post("/channels/{channel_id}/messages", status_code=201)
    async def post_channel_message(
        channel_id: int,
        body: ChannelMessageIn,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        _channel(db, channel_id)
        return await deliver(db, current_user, channel_id, body.model_dump())

    @app.get("/channels/{channel_id}/threads/{root_id}")
    async def list_thread(
        channel_id: int,
        root_id: int,
        limit: int = Query(50, ge=1, le=100),
        before: Optional[int] = None,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        _require_reader(db, channel, current_user)
        root = db.query(Message).filter(Message.id == root_id, Message.group_id == channel_id, Message.thread_root_id.is_(None)).first()
        if not root:
            raise HTTPException(status_code=404, detail="Thread not found")
        now = datetime.now(timezone.utc)
        query = db.query(Message).filter(Message.thread_root_id == root_id, Message.group_id == channel_id)
        query = query.filter(or_(Message.expires_at.is_(None), Message.expires_at > now))
        hidden = db.query(HiddenMessage.message_id).filter(HiddenMessage.user_id == int(current_user.id))
        query = query.filter(~Message.id.in_(hidden))
        if before:
            query = query.filter(Message.id < before)
        replies = query.order_by(Message.id.desc()).limit(limit).all()
        replies.reverse()
        serialize = globals().get("serialize_message") or _message_brief
        return {
            "root_id": root_id,
            "thread_reply_count": int(root.thread_reply_count or 0),
            "thread_last_reply_at": root.thread_last_reply_at.isoformat() if root.thread_last_reply_at else None,
            "following": db.query(ThreadFollow).filter(
                ThreadFollow.user_id == int(current_user.id), ThreadFollow.root_message_id == root_id
            ).first() is not None,
            "replies": [serialize(db, row, int(current_user.id)) for row in replies],
        }

    @app.post("/channels/{channel_id}/threads/{root_id}/follow")
    async def follow_thread(
        channel_id: int, root_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        role = _require_reader(db, channel, current_user)
        if role is None:
            raise HTTPException(status_code=403, detail="You are not a member of this channel")
        root = db.query(Message).filter(Message.id == root_id, Message.group_id == channel_id).first()
        if not root:
            raise HTTPException(status_code=404, detail="Thread not found")
        if not db.query(ThreadFollow).filter(ThreadFollow.user_id == int(current_user.id), ThreadFollow.root_message_id == root_id).first():
            db.add(ThreadFollow(user_id=int(current_user.id), root_message_id=root_id))
            db.commit()
        return {"following": True, "root_id": root_id}

    @app.delete("/channels/{channel_id}/threads/{root_id}/follow")
    async def unfollow_thread(
        channel_id: int, root_id: int,
        current_user=Depends(get_current_user),
        db: Session = Depends(get_database_session),
    ):
        channel = _channel(db, channel_id)
        _require_reader(db, channel, current_user)
        db.query(ThreadFollow).filter(
            ThreadFollow.user_id == int(current_user.id), ThreadFollow.root_message_id == root_id
        ).delete()
        db.commit()
        return {"following": False, "root_id": root_id}


async def _set_archived(channel_id, archived, current_user, db, audit):
    channel = _channel(db, channel_id)
    _require_manager(db, channel, current_user)
    channel.is_archived = archived
    db.commit()
    audit(db, int(current_user.id), "channel_archived" if archived else "channel_unarchived", f"Channel {channel_id}")
    return channel_dict(db, channel, int(current_user.id))


def _set_role(db, channel_id, username, role, current_user):
    channel = _channel(db, channel_id)
    _require_manager(db, channel, current_user)
    target = _user_in_org(db, username, channel.organization_id)
    membership = db.query(GroupMember).filter(
        GroupMember.group_id == channel_id, GroupMember.user_id == target.id
    ).first()
    if not membership:
        raise HTTPException(status_code=404, detail="User is not a member of this channel")
    if membership.role == "owner":
        raise HTTPException(status_code=403, detail="Transfer ownership instead of changing the owner's role")
    actor_role = _role(db, channel_id, int(current_user.id))
    org_admin = is_org_channel_admin(current_user) and same_org(current_user, channel.organization_id)
    action = "promote" if role == "admin" else "demote"
    blocked = member_change_block(actor_role, membership.role, org_admin, action)
    if blocked:
        raise HTTPException(status_code=403, detail=blocked)
    membership.role = role
    db.commit()
    return {"username": username, "role": role}


def _message_brief(db: Session, row: Message, viewer_id: int = 0) -> dict:
    """Fallback shape. The app replaces this with the group message serializer."""
    sender = db.query(User).filter(User.id == row.sender_id).first()
    deleted = bool(getattr(row, "is_deleted", False))
    return {
        "id": int(row.id),
        "sender": getattr(sender, "username", ""),
        "content": "" if deleted else row.encrypted_content,
        "encrypted_key": None if deleted else row.encrypted_key,
        "iv": None if deleted else row.iv,
        "decoy_content": "" if deleted else row.decoy_content,
        "content_type": "deleted" if deleted else row.content_type,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "thread_root_id": row.thread_root_id,
        "is_deleted": deleted,
        "is_edited": bool(getattr(row, "is_edited", False)),
    }


def search_channel_rows(db: Session, user, term: str, limit: int) -> list:
    """Names, topics and descriptions only. Message bodies stay on the client."""
    like = f"%{term.lower()}%"
    from sqlalchemy import func, or_
    query = db.query(Group).filter(
        Group.kind == "channel",
        or_(
            func.lower(Group.name).like(like),
            func.lower(func.coalesce(Group.topic, "")).like(like),
            func.lower(func.coalesce(Group.description, "")).like(like),
        ),
    )
    org_id = getattr(user, "organization_id", None)
    if org_id and not getattr(user, "is_admin", False):
        query = query.filter(Group.organization_id == org_id)
    joined = {row.group_id for row in db.query(GroupMember.group_id).filter(GroupMember.user_id == int(user.id)).all()}
    matched = []
    for channel in query.limit(limit * 3).all():
        visible = channel.id in joined or (
            channel.visibility == "public" and same_org(user, channel.organization_id)
        ) or (is_org_channel_admin(user) and same_org(user, channel.organization_id))
        if visible:
            matched.append(channel)
        if len(matched) >= limit:
            break
    members, _, _ = _channel_stats(db, [int(channel.id) for channel in matched], None)
    out = []
    for channel in matched:
        out.append({
            "id": int(channel.id),
            "name": channel.name,
            "topic": channel.topic,
            "description": channel.description,
            "visibility": channel.visibility,
            "member_count": int(members.get(channel.id, 0)),
        })
        if len(out) >= limit:
            break
    return out


def guard_channel_post(db: Session, group_id: int, user) -> Optional[Group]:
    """Used by the existing group send path so a channel cannot bypass policy."""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group or getattr(group, "kind", "group") != "channel":
        return None
    role = _role(db, group_id, int(user.id))
    if role is None:
        raise HTTPException(status_code=403, detail="You are not a member of this channel")
    org_admin = is_org_channel_admin(user) and same_org(user, group.organization_id)
    block = posting_block(role, group.posting_policy or "everyone", bool(group.is_archived), org_admin)
    if block:
        raise HTTPException(status_code=403, detail=block)
    return group
