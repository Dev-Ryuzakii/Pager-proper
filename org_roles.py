"""Organization roles, permissions and group policies (modelled on Microsoft Teams),
plus contact search scoped to the caller's organization.

Layers, checked in has_permission():
  1. Site admins and the organization account hold everything.
  2. The member's org role (Owner / Admin / Member / Guest or a custom role) grants
     a set of permissions. Members with no role get the org's default role.
  3. Legacy per-user org_privileges (org_privileges.py) still add on top.
  4. Inside a group, the group's policy can switch member- and guest-level
     abilities off (Teams "team settings"). Group owners/admins are not limited
     by their own group's policy.
"""

import hashlib
import re
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, UniqueConstraint, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from database_models import Base, Group, GroupMember, User
from org_privileges import ORG_PRIVILEGES, is_org_account

# ─── Permission catalogue ─────────────────────────────────────────────────────

PERMISSION_CATALOG: Dict[str, Dict[str, str]] = {
    "messaging": {
        "chat_private": "Start 1:1 and private group chats",
        "edit_own_messages": "Edit sent messages",
        "delete_own_messages": "Delete sent messages",
        "delete_any_messages": "Delete anyone's messages (moderation)",
        "share_files": "Share files and media",
        "send_voice_messages": "Send voice messages",
        "urgent_messages": "Send priority/urgent messages",
        "mention_everyone": "Use @everyone / @channel mentions",
        "read_receipts": "Read receipts on",
    },
    "groups_channels": {
        "create_groups": "Create groups in the organization",
        "create_channels": "Create channels",
        "create_private_channels": "Create private channels",
        "edit_channels": "Edit channel name, topic and settings",
        "delete_channels": "Delete and restore channels",
        "add_members": "Add members to groups",
        "remove_members": "Remove members from groups",
        "manage_group_settings": "Change group policies",
        "archive_groups": "Archive groups and channels",
    },
    "meetings": {
        "schedule_meetings": "Schedule meetings",
        "start_instant_meetings": "Start instant meetings and calls",
        "record_meetings": "Record meetings",
        "transcribe_meetings": "Live captions and transcription",
        "screen_share": "Share screen",
        "bypass_lobby": "Skip the waiting room",
        "invite_external": "Invite people outside the organization",
    },
    "whiteboard": {
        "view_org_whiteboard": "View the organization whiteboard",
        "edit_org_whiteboard": "Edit the organization whiteboard",
        "create_group_whiteboards": "Create and edit group whiteboards",
    },
    "ai": {
        "use_ai": "Use Dilarion AI",
        "run_ai_agents": "Send AI agents to complete tasks",
        "ai_agents_for_others": "Let agents act for other members (tasks, reminders)",
    },
    "people": {
        "search_directory": "Search the organization directory",
        "contact_search": "Find colleagues from phone contacts",
        "set_reminders_for_others": "Set reminders for other members",
    },
    "admin": {
        "manage_roles": "Create roles and assign them",
        "assign_tasks": "Assign tasks",
        "broadcast": "Broadcast to the whole organization",
        "call_control": "Mute and remove people in calls",
        "manage_staff": "Manage staff accounts",
        "manage_groups": "Manage every group in the organization",
        "approve_deletions": "Approve account deletion requests",
    },
}

ALL_PERMISSIONS = {p for section in PERMISSION_CATALOG.values() for p in section}

_MEMBER_DEFAULTS = {
    "chat_private", "edit_own_messages", "delete_own_messages", "share_files", "send_voice_messages",
    "urgent_messages", "read_receipts", "create_groups", "create_channels", "create_private_channels",
    "edit_channels", "add_members", "schedule_meetings", "start_instant_meetings", "transcribe_meetings",
    "screen_share", "view_org_whiteboard", "edit_org_whiteboard", "create_group_whiteboards", "use_ai",
    "run_ai_agents", "search_directory", "contact_search",
}
_GUEST_DEFAULTS = {
    "chat_private", "edit_own_messages", "delete_own_messages", "share_files", "send_voice_messages",
    "read_receipts", "screen_share", "view_org_whiteboard", "use_ai",
}

BUILTIN_ROLES = {
    "owner": ("Owner", ALL_PERMISSIONS),
    "admin": ("Admin", ALL_PERMISSIONS - {"manage_roles"}),
    "member": ("Member", _MEMBER_DEFAULTS),
    "guest": ("Guest", _GUEST_DEFAULTS),
}

# Teams-style group settings. Each key maps to the org permission it narrows.
GROUP_MEMBER_SETTINGS = {
    "members_can_create_channels": "create_channels",
    "members_can_edit_channels": "edit_channels",
    "members_can_delete_channels": "delete_channels",
    "members_can_add_members": "add_members",
    "members_can_edit_messages": "edit_own_messages",
    "members_can_delete_messages": "delete_own_messages",
    "members_can_mention_everyone": "mention_everyone",
    "members_can_share_files": "share_files",
    "members_can_start_meetings": "start_instant_meetings",
    "members_can_edit_whiteboard": "create_group_whiteboards",
    "members_can_use_ai": "use_ai",
}
GROUP_GUEST_SETTINGS = {
    "guests_can_create_channels": "create_channels",
    "guests_can_edit_channels": "edit_channels",
    "guests_can_delete_channels": "delete_channels",
    "guests_can_edit_messages": "edit_own_messages",
    "guests_can_delete_messages": "delete_own_messages",
    "guests_can_edit_whiteboard": "create_group_whiteboards",
}
GROUP_DEFAULTS = {
    **{k: True for k in GROUP_MEMBER_SETTINGS},
    "members_can_delete_channels": False,
    "members_can_mention_everyone": False,
    **{k: False for k in GROUP_GUEST_SETTINGS},
    "guests_can_edit_messages": True,
    "guests_can_delete_messages": True,
}


# ─── Tables ───────────────────────────────────────────────────────────────────

class OrgRole(Base):
    __tablename__ = "org_roles"
    __table_args__ = (UniqueConstraint("organization_id", "key", name="uq_org_roles_org_key"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    key = Column(String(40), nullable=False)  # owner/admin/member/guest or custom-<n>
    name = Column(String(80), nullable=False)
    description = Column(String(255), nullable=True)
    permissions = Column(JSON, nullable=False, default=list)
    is_builtin = Column(Boolean, default=False, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())


class OrgRoleAssignment(Base):
    __tablename__ = "org_role_assignments"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("org_roles.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime(timezone=True), default=func.now())


class GroupPolicy(Base):
    __tablename__ = "group_policies"

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True)
    settings = Column(JSON, nullable=False, default=dict)
    updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class ContactMatch(Base):
    """A phone contact of owner_id that matched a member of the same organization.
    Non-matching contacts are never stored."""
    __tablename__ = "contact_matches"
    __table_args__ = (UniqueConstraint("owner_id", "matched_user_id", name="uq_contact_match"),)

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    matched_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    contact_name = Column(String(255), nullable=True)
    phone_hash = Column(String(64), nullable=False)
    synced_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


# ─── Permission logic ─────────────────────────────────────────────────────────

def ensure_builtin_roles(db: Session, org_id: int) -> Dict[str, OrgRole]:
    have = {r.key: r for r in db.query(OrgRole).filter(OrgRole.organization_id == org_id).all()}
    for key, (name, perms) in BUILTIN_ROLES.items():
        if key not in have:
            row = OrgRole(organization_id=org_id, key=key, name=name, permissions=sorted(perms),
                          is_builtin=True, is_default=(key == "member"))
            db.add(row)
            have[key] = row
    db.flush()
    return have


def user_role(db: Session, user) -> Optional[OrgRole]:
    org_id = getattr(user, "organization_id", None)
    if not org_id:
        return None
    a = db.query(OrgRoleAssignment).filter(OrgRoleAssignment.user_id == int(user.id)).first()
    if a:
        role = db.query(OrgRole).filter(OrgRole.id == a.role_id, OrgRole.organization_id == org_id).first()
        if role:
            return role
    role = db.query(OrgRole).filter(OrgRole.organization_id == org_id, OrgRole.is_default == True).first()  # noqa: E712
    if role:
        return role
    return ensure_builtin_roles(db, org_id)["member"]


def _is_superuser(user) -> bool:
    return bool(getattr(user, "is_admin", False)) or is_org_account(user)


def effective_permissions(db: Session, user) -> set:
    if _is_superuser(user):
        return set(ALL_PERMISSIONS)
    role = user_role(db, user)
    perms = set(role.permissions or []) if role else set(_MEMBER_DEFAULTS)
    legacy = getattr(user, "org_privileges", None) or []
    if "*" in legacy:
        perms |= ORG_PRIVILEGES
    else:
        perms |= {p for p in legacy if p in ORG_PRIVILEGES}
    return perms & ALL_PERMISSIONS


def group_settings(db: Session, group_id: int) -> dict:
    row = db.query(GroupPolicy).filter(GroupPolicy.group_id == group_id).first()
    return {**GROUP_DEFAULTS, **((row.settings or {}) if row else {})}


def has_permission(db: Session, user, perm: str, group_id: Optional[int] = None) -> bool:
    if _is_superuser(user):
        return True
    perms = effective_permissions(db, user)
    if perm not in perms:
        return False
    if group_id is None:
        return True
    if "manage_groups" in perms:
        return True
    gm = db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == int(user.id)).first()
    if gm and gm.role in ("owner", "admin"):
        return True
    settings = group_settings(db, group_id)
    role = user_role(db, user)
    table = GROUP_GUEST_SETTINGS if role is not None and role.key == "guest" else GROUP_MEMBER_SETTINGS
    for setting, narrowed in table.items():
        if narrowed == perm and not settings.get(setting, True):
            return False
    return True


def require_permission(db: Session, user, perm: str, group_id: Optional[int] = None):
    if not has_permission(db, user, perm, group_id):
        raise HTTPException(status_code=403, detail=f"Your role does not allow: {perm}")


# ─── Contacts ─────────────────────────────────────────────────────────────────

_DIGITS = re.compile(r"\D+")


def phone_digits(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith("00"):
        raw = raw[2:]
    return _DIGITS.sub("", raw)


def phone_hash(digits: str) -> str:
    return hashlib.sha256(digits.encode()).hexdigest()


def _member_dict(u: User, contact_name: Optional[str] = None) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "full_name": u.full_name,
        "contact_name": contact_name,
        "department": getattr(u, "department", None),
        "profile_picture": getattr(u, "profile_picture_path", None) and f"/users/{u.id}/profile-picture",
    }


# ─── Request bodies ───────────────────────────────────────────────────────────

class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    description: Optional[str] = Field(None, max_length=255)
    permissions: List[str] = []
    base_role: Optional[str] = Field(None, description="Copy permissions from owner/admin/member/guest first")


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=80)
    description: Optional[str] = Field(None, max_length=255)
    permissions: Optional[List[str]] = None
    make_default: bool = False


class RoleAssign(BaseModel):
    role_id: int


class GroupPolicyUpdate(BaseModel):
    settings: Dict[str, bool]


class ContactEntry(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    phones: List[str] = Field(default_factory=list, max_length=20)


class ContactSync(BaseModel):
    contacts: List[ContactEntry] = Field(..., max_length=10000)
    replace: bool = True


# ─── Routes ───────────────────────────────────────────────────────────────────

def install_org_role_routes(app: FastAPI, get_current_user, get_database_session, audit):

    def _org(user) -> int:
        org_id = getattr(user, "organization_id", None)
        if not org_id:
            raise HTTPException(status_code=403, detail="An organization membership is required")
        return int(org_id)

    def _role_dict(r: OrgRole, count: Optional[int] = None) -> dict:
        d = {"id": r.id, "key": r.key, "name": r.name, "description": r.description,
             "permissions": sorted(r.permissions or []), "is_builtin": r.is_builtin, "is_default": r.is_default}
        if count is not None:
            d["member_count"] = count
        return d

    def _clean(perms: List[str]) -> List[str]:
        bad = [p for p in perms if p not in ALL_PERMISSIONS]
        if bad:
            raise HTTPException(status_code=400, detail=f"Unknown permissions: {', '.join(bad[:5])}")
        return sorted(set(perms))

    @app.get("/org/permissions/catalog")
    async def permission_catalog(current_user=Depends(get_current_user)):
        return {
            "permissions": PERMISSION_CATALOG,
            "group_settings": {"member": GROUP_MEMBER_SETTINGS, "guest": GROUP_GUEST_SETTINGS,
                               "defaults": GROUP_DEFAULTS},
        }

    @app.get("/org/me/permissions")
    async def my_permissions(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        role = user_role(db, current_user)
        perms = effective_permissions(db, current_user)
        db.commit()
        return {"role": _role_dict(role) if role else None, "permissions": sorted(perms)}

    @app.get("/org/roles")
    async def list_roles(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        ensure_builtin_roles(db, org_id)
        db.commit()
        rows = db.query(OrgRole).filter(OrgRole.organization_id == org_id).order_by(OrgRole.id).all()
        out = []
        for r in rows:
            n = db.query(OrgRoleAssignment).filter(OrgRoleAssignment.role_id == r.id).count()
            out.append(_role_dict(r, n))
        return {"roles": out}

    @app.post("/org/roles", status_code=201)
    async def create_role(body: RoleCreate, current_user=Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_roles")
        perms = set(_clean(body.permissions))
        if body.base_role:
            if body.base_role not in BUILTIN_ROLES:
                raise HTTPException(status_code=400, detail="base_role must be owner, admin, member or guest")
            perms |= BUILTIN_ROLES[body.base_role][1]
        n = db.query(OrgRole).filter(OrgRole.organization_id == org_id).count()
        row = OrgRole(organization_id=org_id, key=f"custom-{n + 1}-{hashlib.sha1(body.name.encode()).hexdigest()[:6]}",
                      name=body.name.strip(), description=body.description, permissions=sorted(perms))
        db.add(row)
        db.flush()
        audit(db, current_user.id, "org_role_created", f"Role '{row.name}' created")
        db.commit()
        return _role_dict(row, 0)

    @app.patch("/org/roles/{role_id}")
    async def update_role(role_id: int, body: RoleUpdate, current_user=Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_roles")
        row = db.query(OrgRole).filter(OrgRole.id == role_id, OrgRole.organization_id == org_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Role not found")
        if row.key == "owner" and body.permissions is not None:
            raise HTTPException(status_code=400, detail="The Owner role always holds every permission")
        if body.name is not None:
            row.name = body.name.strip()
        if body.description is not None:
            row.description = body.description
        if body.permissions is not None:
            row.permissions = _clean(body.permissions)
        if body.make_default:
            if row.key in ("owner", "admin"):
                raise HTTPException(status_code=400, detail="Owner/Admin cannot be the default role")
            db.query(OrgRole).filter(OrgRole.organization_id == org_id).update({OrgRole.is_default: False})
            row.is_default = True
        audit(db, current_user.id, "org_role_updated", f"Role '{row.name}' updated")
        db.commit()
        return _role_dict(row)

    @app.delete("/org/roles/{role_id}", status_code=204)
    async def delete_role(role_id: int, current_user=Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_roles")
        row = db.query(OrgRole).filter(OrgRole.id == role_id, OrgRole.organization_id == org_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Role not found")
        if row.is_builtin:
            raise HTTPException(status_code=400, detail="Built-in roles cannot be deleted")
        if row.is_default:
            raise HTTPException(status_code=400, detail="Pick another default role first")
        db.query(OrgRoleAssignment).filter(OrgRoleAssignment.role_id == row.id).delete()
        audit(db, current_user.id, "org_role_deleted", f"Role '{row.name}' deleted")
        db.delete(row)
        db.commit()

    @app.put("/org/members/{user_id}/role")
    async def assign_role(user_id: int, body: RoleAssign, current_user=Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_roles")
        member = db.query(User).filter(User.id == user_id, User.organization_id == org_id).first()
        if not member:
            raise HTTPException(status_code=404, detail="Member not found in your organization")
        role = db.query(OrgRole).filter(OrgRole.id == body.role_id, OrgRole.organization_id == org_id).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        caller_role = user_role(db, current_user)
        if role.key == "owner" and not _is_superuser(current_user) and (not caller_role or caller_role.key != "owner"):
            raise HTTPException(status_code=403, detail="Only an owner can make someone an owner")
        a = db.query(OrgRoleAssignment).filter(OrgRoleAssignment.user_id == member.id).first()
        if a:
            a.role_id = role.id
            a.assigned_by_id = current_user.id
        else:
            db.add(OrgRoleAssignment(user_id=member.id, role_id=role.id, assigned_by_id=current_user.id))
        audit(db, current_user.id, "org_role_assigned", f"{member.username} -> {role.name}")
        db.commit()
        return {"user_id": member.id, "role": _role_dict(role)}

    @app.get("/org/members/roles")
    async def member_roles(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_roles")
        roles = {r.id: r for r in db.query(OrgRole).filter(OrgRole.organization_id == org_id).all()}
        assigned = {a.user_id: a.role_id for a in db.query(OrgRoleAssignment).join(
            OrgRole, OrgRole.id == OrgRoleAssignment.role_id).filter(OrgRole.organization_id == org_id).all()}
        default = next((r for r in roles.values() if r.is_default), None)
        out = []
        for u in db.query(User).filter(User.organization_id == org_id, User.is_active == True).all():  # noqa: E712
            r = roles.get(assigned.get(u.id)) or default
            out.append({"user_id": u.id, "username": u.username, "full_name": u.full_name,
                        "role_id": r.id if r else None, "role_name": r.name if r else None})
        return {"members": out}

    # Group policies (Teams "team settings")

    def _group_in_org(db: Session, group_id: int, org_id: int) -> Group:
        g = db.query(Group).filter(Group.id == group_id).first()
        if not g or (g.organization_id and int(g.organization_id) != org_id):
            raise HTTPException(status_code=404, detail="Group not found")
        return g

    @app.get("/org/groups/policies")
    async def list_group_policies(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        """Every group and channel in the organization with its settings, for the org portal."""
        org_id = _org(current_user)
        require_permission(db, current_user, "manage_groups")
        groups = db.query(Group).filter(Group.organization_id == org_id, Group.is_archived == False).order_by(Group.name).all()  # noqa: E712
        stored = {p.group_id: p.settings or {} for p in db.query(GroupPolicy).filter(
            GroupPolicy.group_id.in_([g.id for g in groups] or [-1])).all()}
        counts = dict(db.query(GroupMember.group_id, func.count(GroupMember.id)).filter(
            GroupMember.group_id.in_([g.id for g in groups] or [-1])).group_by(GroupMember.group_id).all())
        return {"groups": [{
            "id": g.id, "name": g.name, "kind": g.kind, "member_count": int(counts.get(g.id, 0)),
            "settings": {**GROUP_DEFAULTS, **stored.get(g.id, {})},
        } for g in groups]}

    @app.get("/groups/{group_id}/policy")
    async def get_group_policy(group_id: int, current_user=Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        _group_in_org(db, group_id, org_id)
        return {"group_id": group_id, "settings": group_settings(db, group_id),
                "can_edit": has_permission(db, current_user, "manage_group_settings", group_id)}

    @app.put("/groups/{group_id}/policy")
    async def put_group_policy(group_id: int, body: GroupPolicyUpdate, current_user=Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        _group_in_org(db, group_id, org_id)
        gm = db.query(GroupMember).filter(GroupMember.group_id == group_id,
                                          GroupMember.user_id == int(current_user.id)).first()
        is_group_admin = gm is not None and gm.role in ("owner", "admin")
        if not (has_permission(db, current_user, "manage_groups")
                or (is_group_admin and has_permission(db, current_user, "manage_group_settings"))):
            raise HTTPException(status_code=403, detail="Only group owners/admins with manage_group_settings can change this")
        unknown = [k for k in body.settings if k not in GROUP_DEFAULTS]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown settings: {', '.join(unknown[:5])}")
        row = db.query(GroupPolicy).filter(GroupPolicy.group_id == group_id).first()
        merged = {**((row.settings or {}) if row else {}), **body.settings}
        if row:
            row.settings = merged
            row.updated_by_id = current_user.id
        else:
            db.add(GroupPolicy(group_id=group_id, settings=merged, updated_by_id=current_user.id))
        audit(db, current_user.id, "group_policy_updated", f"group {group_id}: {sorted(body.settings)}")
        db.commit()
        return {"group_id": group_id, "settings": {**GROUP_DEFAULTS, **merged}}

    # Contacts: find colleagues from the phone's address book

    @app.post("/contacts/sync")
    async def sync_contacts(body: ContactSync, current_user=Depends(get_current_user),
                            db: Session = Depends(get_database_session)):
        """The app uploads its address book. Only entries matching an active member of
        the caller's organization are kept; everything else is discarded unread."""
        org_id = _org(current_user)
        require_permission(db, current_user, "contact_search")
        members = db.query(User).filter(User.organization_id == org_id, User.is_active == True,  # noqa: E712
                                        User.id != int(current_user.id)).all()
        exact: Dict[str, User] = {}
        suffix: Dict[str, List[User]] = {}
        for u in members:
            d = phone_digits(u.phone_number or "")
            if len(d) < 7:
                continue
            exact[d] = u
            suffix.setdefault(d[-9:], []).append(u)
        found: Dict[int, tuple] = {}
        for c in body.contacts:
            for raw in c.phones:
                d = phone_digits(raw)
                if len(d) < 7:
                    continue
                u = exact.get(d)
                if u is None:
                    cands = suffix.get(d[-9:], [])
                    u = cands[0] if len(cands) == 1 else None  # ambiguous local number: skip
                if u is not None and u.id not in found:
                    found[u.id] = ((c.name or "").strip()[:255] or None, phone_hash(phone_digits(u.phone_number)))
        if body.replace:
            db.query(ContactMatch).filter(ContactMatch.owner_id == int(current_user.id)).delete()
            db.flush()
        existing = {m.matched_user_id: m for m in db.query(ContactMatch).filter(
            ContactMatch.owner_id == int(current_user.id)).all()}
        for uid, (name, h) in found.items():
            m = existing.get(uid)
            if m:
                m.contact_name = name or m.contact_name
                m.phone_hash = h
                m.organization_id = org_id
            else:
                db.add(ContactMatch(owner_id=int(current_user.id), matched_user_id=uid,
                                    organization_id=org_id, contact_name=name, phone_hash=h))
        db.commit()
        return {"uploaded": len(body.contacts), "matched": len(found)}

    @app.get("/contacts")
    async def list_contact_matches(current_user=Depends(get_current_user),
                                   db: Session = Depends(get_database_session)):
        org_id = _org(current_user)
        rows = (db.query(ContactMatch, User).join(User, User.id == ContactMatch.matched_user_id)
                .filter(ContactMatch.owner_id == int(current_user.id), ContactMatch.organization_id == org_id,
                        User.organization_id == org_id, User.is_active == True)  # noqa: E712
                .order_by(ContactMatch.contact_name).all())
        return {"contacts": [_member_dict(u, m.contact_name) for m, u in rows]}

    @app.get("/contacts/search")
    async def search_contacts(q: str = Query(..., min_length=1, max_length=100),
                              current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        """Search colleagues saved in your phone contacts by the name you saved them
        under, their Dilarion name, username or phone number. Strictly your organization."""
        org_id = _org(current_user)
        require_permission(db, current_user, "contact_search")
        like = f"%{q.strip()}%"
        digits = phone_digits(q)
        conds = [ContactMatch.contact_name.ilike(like), User.full_name.ilike(like), User.username.ilike(like)]
        if len(digits) >= 3:
            conds.append(User.phone_number.like(f"%{digits}%"))
        rows = (db.query(ContactMatch, User).join(User, User.id == ContactMatch.matched_user_id)
                .filter(ContactMatch.owner_id == int(current_user.id), ContactMatch.organization_id == org_id,
                        User.organization_id == org_id, User.is_active == True, or_(*conds))  # noqa: E712
                .limit(50).all())
        return {"results": [_member_dict(u, m.contact_name) for m, u in rows]}

    @app.delete("/contacts", status_code=204)
    async def revoke_contacts(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        """The user turned contact access off: forget every match."""
        db.query(ContactMatch).filter(ContactMatch.owner_id == int(current_user.id)).delete()
        db.commit()
