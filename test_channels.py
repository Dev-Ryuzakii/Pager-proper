"""Channel permissions, join rules, archive, and thread counts. SQLite, no Postgres."""

import unittest
from datetime import datetime

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import channels
from database_models import Base, Group, GroupMember, Message, Organization, User


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
    assert channels.can_join("private", False) == "Private channels are invite-only"
    assert channels.can_leave("owner") == "Transfer ownership before leaving"
    assert channels.can_leave("member") is None
    assert channels.slugify("Launch Plans!") == "launch-plans"


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

        channels.install_channel_routes(
            app, current_user, get_db,
            lambda db, uid, event, description: self.audit.append((event, description)),
            notify,
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
        thread = self.client.get(f"/channels/{channel_id}/threads/{root_id}")
        self.assertEqual(thread.status_code, 200)
        self.assertEqual(thread.json()["thread_reply_count"], 1)
        self.assertEqual(len(thread.json()["replies"]), 1)
        self.assertEqual(self.events[-1][1]["type"], "thread_reply")

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
        self.assertEqual(root.thread_reply_count, 1)
        self.assertIsInstance(root.thread_last_reply_at, datetime)


if __name__ == "__main__":
    org_admin_cases()
    posting_cases()
    unittest.main()
