"""Channel permissions, join rules, archive, and thread counts. SQLite, no Postgres."""

import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import channels
from sqlalchemy.exc import IntegrityError

from database_models import Base, Group, GroupMember, HiddenMessage, Message, Organization, User


def org_admin_cases():
    viewer = type("U", (), {"is_admin": False, "user_type": "mobile", "organization_role": "viewer", "org_privileges": None})()
    org = type("U", (), {"is_admin": False, "user_type": "organization", "organization_role": "viewer", "org_privileges": None})()
    groups = type("U", (), {"is_admin": False, "user_type": "mobile", "organization_role": "member", "org_privileges": ["manage_groups"]})()
    staff = type("U", (), {"is_admin": False, "user_type": "mobile", "organization_role": "member", "org_privileges": ["manage_staff"]})()
    star = type("U", (), {"is_admin": False, "user_type": "mobile", "organization_role": "member", "org_privileges": ["*"]})()
    site = type("U", (), {"is_admin": True, "user_type": "mobile", "organization_role": "member", "org_privileges": None})()
    member = type("U", (), {"is_admin": False, "user_type": "mobile", "organization_role": "member", "org_privileges": None})()
    assert channels.is_org_channel_admin(viewer) is False
    assert channels.is_org_channel_admin(org) is True
    assert channels.is_org_channel_admin(groups) is True
    assert channels.is_org_channel_admin(star) is True
    assert channels.is_org_channel_admin(site) is True
    assert channels.is_org_channel_admin(member) is False
    import meeting_notes
    assert meeting_notes._can_edit_org(viewer) is False
    assert meeting_notes._can_edit_org(groups) is False
    assert meeting_notes._can_edit_org(staff) is True
    assert meeting_notes._can_edit_org(org) is True
    assert meeting_notes._can_edit_org(site) is True


def posting_cases():
    assert channels.posting_block("member", "everyone", False, False) is None
    assert channels.posting_block("member", "admins", False, False) == "Only channel admins can post here"
    assert channels.posting_block("admin", "admins", False, False) is None
    assert channels.posting_block("owner", "admins", False, False) is None
    assert channels.posting_block(None, "everyone", False, True) is None
    assert channels.posting_block("owner", "everyone", True, True) == "This channel is archived"
    assert channels.can_join("public", False) is None
    assert channels.can_join("public", False, archived=True) == "This channel is archived"
    assert channels.can_join("private", False) == "Private channels are invite-only"
    assert channels.thread_push_recipients([2, 3], 4, 3, [2]) == [4]
    assert channels.can_leave("owner") == "Transfer ownership before leaving"
    assert channels.can_leave("member") is None
    assert channels.member_change_block("admin", "member", False, "remove") is None
    assert channels.member_change_block("admin", "admin", False, "demote") == "Only the owner can change a channel admin"
    assert channels.member_change_block("admin", "member", False, "promote") == "Only the owner can promote a channel admin"
    assert channels.member_change_block("owner", "admin", False, "demote") is None
    assert channels.member_change_block("admin", "admin", True, "remove") is None
    assert channels.reply_target_block(None, 1) == "Reply target is not in this conversation"
    assert channels.reply_target_block(2, 1) == "Reply target is not in this conversation"
    assert channels.reply_target_block(1, 1) is None
    assert channels.slugify("Launch Plans!") == "launch-plans"
    assert channels.is_group_admin_role("admin") is True
    assert channels.is_group_admin_role("owner") is True
    assert channels.is_group_admin_role("member") is False
    assert channels.is_group_admin_role(None) is False
    assert channels.in_channel_timeline("channel", None) is True
    assert channels.in_channel_timeline("channel", 4) is False
    assert channels.in_channel_timeline("group", 4) is True
    assert channels.group_write_uses_channel_api("channel") is True
    assert channels.group_write_uses_channel_api("group") is False


class ChannelHttpTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)
        self.db = self.Session()
        org = Organization(
            name="Acme", slug="acme", contact_name="A", contact_email="a@acme.test",
        )
        self.db.add(org)
        self.db.flush()
        self.org_id = org.id
        self.users = {}
        for name, role, admin, privs in (
            ("owner", "member", False, None),
            ("admin", "member", False, None),
            ("member", "member", False, None),
            ("outsider", "member", False, None),
            ("orgadmin", "admin", False, ["manage_groups"]),
            ("stranger", "member", False, None),
        ):
            org_id = None if name == "stranger" else self.org_id
            if name == "outsider":
                org_id = self.org_id
            user = User(
                username=name,
                phone_number=f"+1555000{len(self.users)}",
                organization_id=org_id,
                organization_role=role,
                is_admin=admin,
                org_privileges=privs,
                is_active=True,
            )
            self.db.add(user)
            self.db.flush()
            self.users[name] = user
        self.db.commit()
        self.holder = {"user": self.users["owner"]}
        self.audit = []
        self.events = []
        app = FastAPI()

        def current_user():
            return self.holder["user"]

        def get_db():
            yield self.db

        async def notify(user_ids, payload):
            self.events.append((list(user_ids), payload))

        async def deliver(db, user, group_id, fields):
            channels.guard_channel_post(db, group_id, user)
            reply_to = fields.get("reply_to_message_id")
            if reply_to:
                target = db.query(Message).filter(Message.id == reply_to).first()
                blocked = channels.reply_target_block(getattr(target, "group_id", None), group_id)
                if blocked:
                    from fastapi import HTTPException
                    raise HTTPException(status_code=400, detail=blocked)
            root = None
            if fields.get("thread_root_id"):
                root = db.query(Message).filter(
                    Message.id == fields["thread_root_id"], Message.group_id == group_id
                ).first()
                if not root or root.thread_root_id is not None:
                    from fastapi import HTTPException
                    raise HTTPException(status_code=404, detail="Thread not found")
            message = Message(
                sender_id=int(user.id), group_id=group_id,
                encrypted_content=fields.get("message") or "",
                thread_root_id=root.id if root else None,
                reply_to_message_id=fields.get("reply_to_message_id"),
                delivered=True, read=False,
            )
            db.add(message)
            if root:
                channels.apply_thread_reply(db, int(root.id))
            db.commit()
            db.refresh(message)
            member_ids = [row.user_id for row in db.query(GroupMember.user_id).filter(GroupMember.group_id == group_id).all()]
            await notify(member_ids, {
                "type": "new_group_message",
                "data": {
                    "message_id": int(message.id),
                    "thread_root_id": int(root.id) if root else None,
                    "thread_reply_count": int(root.thread_reply_count) if root else 0,
                },
            })
            return {
                "status": "sent",
                "message_id": int(message.id),
                "thread_root_id": int(root.id) if root else None,
                "thread_reply_count": int(root.thread_reply_count) if root else 0,
            }

        channels.install_channel_routes(
            app, current_user, get_db,
            lambda db, uid, event, description: self.audit.append((event, description)),
            notify, deliver,
        )
        self.client = TestClient(app)

    def tearDown(self):
        self.db.close()

    def _as(self, name):
        self.holder["user"] = self.users[name]

    def _create(self, visibility="public", policy="everyone"):
        self._as("owner")
        res = self.client.post("/channels", json={
            "name": "Launch Plans",
            "topic": "Friday ship",
            "description": "Release talk",
            "visibility": visibility,
            "posting_policy": policy,
            "members": ["admin", "member"],
        })
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def test_roles_join_policy_archive_and_threads(self):
        created = self._create(policy="admins")
        channel_id = created["id"]
        self.assertEqual(created["my_role"], "owner")
        self.assertEqual(created["slug"], "launch-plans")
        self.assertTrue(any(event == "channel_created" for event, _ in self.audit))
        self.assertIn(self.users["member"].id, self.events[0][0])
        self._as("owner")
        archived_join = self.client.post(f"/channels/{channel_id}/archive")
        self.assertEqual(archived_join.status_code, 200)
        self._as("outsider")
        self.assertEqual(self.client.post(f"/channels/{channel_id}/join").status_code, 403)
        self._as("owner")
        self.assertEqual(self.client.post(f"/channels/{channel_id}/unarchive").status_code, 200)

        self._as("stranger")
        self.assertEqual(self.client.get(f"/channels/{channel_id}").status_code, 403)

        self._as("outsider")
        self.assertEqual(self.client.post(f"/channels/{channel_id}/messages", json={"message": "hi"}).status_code, 403)

        self._as("member")
        blocked = self.client.post(f"/channels/{channel_id}/messages", json={"message": "secret"})
        self.assertEqual(blocked.status_code, 403)

        self._as("owner")
        self.assertEqual(self.client.post(f"/channels/{channel_id}/members/admin/promote").status_code, 200)
        self._as("admin")
        posted = self.client.post(f"/channels/{channel_id}/messages", json={"message": "cipher-root"})
        self.assertEqual(posted.status_code, 201, posted.text)
        root_id = posted.json()["message_id"]

        reply = self.client.post(f"/channels/{channel_id}/messages", json={
            "message": "cipher-reply", "thread_root_id": root_id,
        })
        self.assertEqual(reply.status_code, 201, reply.text)
        self.assertEqual(reply.json()["thread_reply_count"], 1)
        second = self.client.post(f"/channels/{channel_id}/messages", json={
            "message": "cipher-reply-2", "thread_root_id": root_id,
        })
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(second.json()["thread_reply_count"], 2)
        thread = self.client.get(f"/channels/{channel_id}/threads/{root_id}")
        self.assertEqual(thread.status_code, 200)
        self.assertEqual(thread.json()["thread_reply_count"], 2)
        self.assertEqual(len(thread.json()["replies"]), 2)
        self.assertEqual(self.events[-1][1]["type"], "new_group_message")
        self.assertEqual(self.events[-1][1]["data"]["thread_root_id"], root_id)

        follow = self.client.post(f"/channels/{channel_id}/threads/{root_id}/follow")
        self.assertEqual(follow.status_code, 200)
        self.assertTrue(self.client.get(f"/channels/{channel_id}/threads/{root_id}").json()["following"])

        self._as("owner")
        archived = self.client.post(f"/channels/{channel_id}/archive")
        self.assertEqual(archived.status_code, 200, archived.text)
        self.assertTrue(any(event == "channel_archived" for event, _ in self.audit))
        self._as("admin")
        self.assertEqual(
            self.client.post(f"/channels/{channel_id}/messages", json={"message": "later"}).status_code,
            403,
        )

        self._as("orgadmin")
        self.assertEqual(self.client.post(f"/channels/{channel_id}/unarchive").status_code, 200)
        listed = self.client.get("/channels")
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(row["id"] == channel_id for row in listed.json()))

        private = self._create(visibility="private")
        self._as("outsider")
        self.assertEqual(self.client.post(f"/channels/{private['id']}/join").status_code, 403)
        self._as("owner")
        self.assertEqual(self.client.post(f"/channels/{created['id']}/leave").status_code, 409)
        root = self.db.query(Message).filter(Message.id == root_id).one()
        self.assertEqual(root.thread_reply_count, 2)
        self.assertIsInstance(root.thread_last_reply_at, datetime)

    def test_slug_unique_per_organization(self):
        first = self._create()
        self._as("owner")
        second = self.client.post("/channels", json={
            "name": "Launch Plans", "visibility": "public", "posting_policy": "everyone",
        })
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(second.json()["slug"], "launch-plans-2")
        dup = Group(
            name="other", created_by=self.users["owner"].id, kind="channel",
            organization_id=self.org_id, slug=first["slug"], visibility="public",
            posting_policy="everyone", is_archived=False,
        )
        self.db.add(dup)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_thread_filters_hidden_expired_and_scrubs_deleted(self):
        created = self._create()
        channel_id = created["id"]
        self._as("member")
        root = self.client.post(f"/channels/{channel_id}/messages", json={"message": "root"}).json()
        reply = self.client.post(f"/channels/{channel_id}/messages", json={
            "message": "gone", "thread_root_id": root["message_id"],
        }).json()
        row = self.db.query(Message).filter(Message.id == reply["message_id"]).one()
        row.is_deleted = True
        row.encrypted_content = "cipher-secret"
        hidden = self.client.post(f"/channels/{channel_id}/messages", json={
            "message": "hidden", "thread_root_id": root["message_id"],
        }).json()
        self.db.add(HiddenMessage(user_id=self.users["member"].id, message_id=hidden["message_id"]))
        expired = self.client.post(f"/channels/{channel_id}/messages", json={
            "message": "old", "thread_root_id": root["message_id"],
        }).json()
        old = self.db.query(Message).filter(Message.id == expired["message_id"]).one()
        old.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        self.db.commit()
        page = self.client.get(f"/channels/{channel_id}/threads/{root['message_id']}").json()
        ids = [item["id"] for item in page["replies"]]
        self.assertIn(reply["message_id"], ids)
        self.assertNotIn(hidden["message_id"], ids)
        self.assertNotIn(expired["message_id"], ids)
        shown = next(item for item in page["replies"] if item["id"] == reply["message_id"])
        self.assertEqual(shown["content"], "")
        self.assertTrue(shown["is_deleted"])


if __name__ == "__main__":
    org_admin_cases()
    posting_cases()
    unittest.main()
