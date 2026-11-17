"""Self chat, recording cards, and the recording file route. SQLite, no Postgres."""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import self_dm
from database_models import (
    Base,
    ChatSettings,
    ConferenceParticipant,
    ConferenceSession,
    Meeting,
    MeetingRecording,
    Message,
    Organization,
    RetentionPolicy,
    User,
)


class SelfDmTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.org = Organization(name="Acme", slug="acme-self", contact_name="A", contact_email="a@acme.test")
        self.other_org = Organization(name="Other", slug="other-self", contact_name="O", contact_email="o@other.test")
        self.db.add_all([self.org, self.other_org])
        self.db.flush()
        self.users = {}
        for name, org in (
            ("me", self.org), ("sam", self.org), ("waiting", self.org),
            ("outsider", self.other_org),
        ):
            user = User(
                username=name, phone_number=f"+1777{len(self.users):04d}",
                organization_id=org.id, is_active=True,
            )
            self.db.add(user)
            self.db.flush()
            self.users[name] = user
        self.db.commit()

    def tearDown(self):
        self.db.close()

    def test_self_conversation_is_first_and_present_when_empty(self):
        me = self.users["me"]
        listed = self_dm.list_conversations(self.db, me)
        self.assertEqual(listed[0]["partner_username"], "me")
        self.assertTrue(listed[0]["is_self"])
        self.assertEqual(listed[0]["display_name"], "You")
        self.assertIsNone(listed[0]["last_message"])
        self.assertEqual(listed[0]["unread_count"], 0)
        self.assertEqual(len(listed), 1)

        self_dm.create_direct_message(self.db, me.id, self.users["sam"].id, "hello", disappear_after_hours=1)
        listed = self_dm.list_conversations(self.db, me)
        self.assertTrue(listed[0]["is_self"])
        self.assertFalse(listed[1]["is_self"])
        self.assertEqual(listed[1]["partner_username"], "sam")
        self.assertEqual(listed[1]["display_name"], "sam")
        self.assertEqual(listed[1]["username"], "sam")

        sams = self_dm.list_conversations(self.db, self.users["sam"])
        self.assertTrue(sams[0]["is_self"])
        self.assertEqual(sams[0]["partner_username"], "sam")
        self.assertNotIn("me", [item["partner_username"] for item in sams if item["is_self"]])

    def test_sending_to_self_never_expires(self):
        me = self.users["me"]
        note = self_dm.create_direct_message(
            self.db, me.id, me.id, "note to self", disappear_after_hours=12,
        )
        self.assertIsNone(note.expires_at)
        self.assertFalse(note.auto_delete)
        self.assertTrue(note.delivered)
        self.assertTrue(note.read)
        flags = self_dm.direct_flags(me.id, me.id, 12)
        self.assertIsNone(flags["expires_at"])
        self.assertFalse(flags["auto_delete"])

        other = self_dm.create_direct_message(self.db, me.id, self.users["sam"].id, "not mine")
        rows = self.db.query(Message).filter(self_dm.dm_clause(me.id, me.id)).order_by(Message.timestamp.asc()).all()
        self.assertEqual([row.id for row in rows], [note.id])
        self.assertNotIn(other.id, [row.id for row in rows])

        self.db.add(ChatSettings(
            user_id=me.id, peer_username="me",
            deleted_before=datetime.now(timezone.utc) + timedelta(minutes=5),
        ))
        self.db.commit()
        listed = self_dm.list_conversations(self.db, me)
        self.assertTrue(listed[0]["is_self"])
        self.assertIsNone(listed[0]["last_message"])

    def _recording(self, status="completed"):
        me = self.users["me"]
        conference = ConferenceSession(created_by_user_id=me.id, kind="meeting")
        self.db.add(conference)
        self.db.flush()
        self.db.add(Meeting(
            creator_id=me.id, title="Weekly sync", scheduled_at=datetime(2026, 11, 17, 10, 0),
            join_code=f"sync{conference.id}", conference_id=conference.id,
        ))
        started = datetime(2026, 11, 17, 10, 0)
        ended = datetime(2026, 11, 17, 10, 42, 10)
        for name, status_value, active, left in (
            ("me", "admitted", True, None),
            ("sam", "admitted", False, ended),
            ("waiting", "waiting", True, None),
            ("outsider", "admitted", True, None),
        ):
            self.db.add(ConferenceParticipant(
                conference_id=conference.id, user_id=self.users[name].id,
                status=status_value, is_active=active, left_at=left,
            ))
        recording = MeetingRecording(
            conference_id=conference.id, started_by_user_id=me.id, egress_id="eg-1",
            status=status, file_path="meeting_recordings/missing.mp4",
            started_at=started, ended_at=ended,
        )
        self.db.add(recording)
        self.db.commit()
        return recording

    def test_recording_card_once_per_admitted_participant(self):
        recording = self._recording()
        first = self_dm.deliver_recording_cards(self.db, recording.id, "/srv/recordings")
        second = self_dm.deliver_recording_cards(self.db, recording.id, "/srv/recordings")
        self.assertEqual(len(second), 0)
        recipients = {row.recipient_id for row in first}
        self.assertEqual(recipients, {self.users["me"].id, self.users["sam"].id})
        self.assertEqual(
            self.db.query(Message).filter(Message.content_type == "meeting_recording").count(), 2,
        )
        card = json.loads(first[0].encrypted_content)
        self.assertEqual(card["kind"], "meeting_recording")
        self.assertEqual(card["meeting_title"], "Weekly sync")
        self.assertEqual(card["host_username"], "me")
        self.assertEqual(card["started_at"], "2026-11-17T10:00:00Z")
        self.assertEqual(card["ended_at"], "2026-11-17T10:42:10Z")
        self.assertEqual(card["duration_seconds"], 2530)
        self.assertIsNone(card["file_size"])
        self.assertEqual(card["download_path"], f"/meetings/recordings/{recording.id}/file")
        self.assertEqual(first[0].decoy_content, "🎥 Meeting recording")
        self.assertEqual(first[0].sender_id, first[0].recipient_id)
        self.assertIsNone(first[0].expires_at)
        self.assertTrue(first[0].read)
        sam_list = self_dm.list_conversations(self.db, self.users["sam"])
        self.assertEqual(sam_list[0]["display_name"], "You")
        self.assertEqual(sam_list[0]["unread_count"], 0)

    def test_notes_card_only_on_success(self):
        recording = self._recording()
        recording.ai_status = "failed"
        recording.notes_json = '{"summary":"secret transcript text"}'
        self.db.commit()
        self.assertEqual(self_dm.deliver_notes_cards(self.db, recording.id), [])
        recording.ai_status = "done"
        recording.notes_json = json.dumps({
            "summary": "S" * 500,
            "key_points": ["a", "b", "c", "d", "e", "f", ""],
            "action_items": [{"task": "one"}, {"task": "two"}, {"task": "three"}, {"task": "four"}],
        })
        self.db.commit()
        created = self_dm.deliver_notes_cards(self.db, recording.id)
        self.assertEqual(len(created), 2)
        self.assertEqual(self_dm.deliver_notes_cards(self.db, recording.id), [])
        card = json.loads(created[0].encrypted_content)
        self.assertEqual(card["kind"], "meeting_notes")
        self.assertEqual(len(card["summary"]), 400)
        self.assertEqual(card["key_points"], ["a", "b", "c", "d", "e"])
        self.assertEqual(card["action_item_count"], 4)
        self.assertEqual(created[0].content_type, "meeting_notes")
        self.assertEqual(created[0].decoy_content, "📝 Meeting notes")


class RecordingFileTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.tmp = tempfile.TemporaryDirectory()
        org = Organization(name="Acme", slug="acme-file", contact_name="A", contact_email="a@file.test")
        self.db.add(org)
        self.db.flush()
        self.users = {}
        for name in ("host", "stranger"):
            user = User(username=name, phone_number=f"+1888{len(self.users):04d}", organization_id=org.id, is_active=True)
            self.db.add(user)
            self.db.flush()
            self.users[name] = user
        conference = ConferenceSession(created_by_user_id=self.users["host"].id, kind="meeting")
        self.db.add(conference)
        self.db.flush()
        self.db.add(ConferenceParticipant(
            conference_id=conference.id, user_id=self.users["host"].id, status="admitted", is_active=True,
        ))
        self.db.add(Meeting(
            creator_id=self.users["host"].id, title="Weekly sync",
            scheduled_at=datetime(2026, 11, 17, 10, 0), join_code="file1", conference_id=conference.id,
        ))
        self.ready = os.path.join(self.tmp.name, "ready.mp4")
        with open(self.ready, "wb") as handle:
            handle.write(b"0123456789")
        self.empty = os.path.join(self.tmp.name, "empty.mp4")
        open(self.empty, "wb").close()
        self.processing = MeetingRecording(
            conference_id=conference.id, started_by_user_id=self.users["host"].id,
            egress_id="eg-p", status="recording", file_path=os.path.join(self.tmp.name, "nope.mp4"),
        )
        self.completed = MeetingRecording(
            conference_id=conference.id, started_by_user_id=self.users["host"].id,
            egress_id="eg-c", status="completed", file_path=self.ready,
            started_at=datetime(2026, 11, 17, 10, 0),
        )
        self.growing = MeetingRecording(
            conference_id=conference.id, started_by_user_id=self.users["host"].id,
            egress_id="eg-z", status="completed", file_path=self.empty,
        )
        self.db.add_all([self.processing, self.completed, self.growing])
        self.db.commit()
        holder = {"token": "host"}

        def resolve(_db, token):
            return self.users["host"] if token == "host" else self.users["stranger"]

        def current_user():
            return self.users["host"] if holder["token"] == "host" else self.users["stranger"]

        def get_db():
            yield self.db

        app = FastAPI()
        self_dm.install_recording_library_routes(app, current_user, resolve, get_db, lambda: self.tmp.name)
        self.client = TestClient(app)
        self.holder = holder

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_file_route_forbidden_processing_and_range(self):
        missing = self.client.get("/meetings/recordings/999999/file", headers={"Authorization": "Bearer host"})
        self.assertEqual(missing.status_code, 404)

        denied = self.client.get(
            f"/meetings/recordings/{self.completed.id}/file",
            headers={"Authorization": "Bearer stranger"},
        )
        self.assertEqual(denied.status_code, 403)

        processing = self.client.get(
            f"/meetings/recordings/{self.processing.id}/file",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(processing.status_code, 409)
        self.assertEqual(processing.json()["detail"], "Recording is still being processed")

        empty = self.client.get(
            f"/meetings/recordings/{self.growing.id}/file",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(empty.status_code, 409)

        full = self.client.get(
            f"/meetings/recordings/{self.completed.id}/file",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(full.status_code, 200)
        self.assertEqual(full.content, b"0123456789")
        self.assertEqual(full.headers["content-type"], "video/mp4")
        self.assertIn("inline;", full.headers["content-disposition"])
        self.assertIn("Weekly-sync-2026-11-17.mp4", full.headers["content-disposition"])

        partial = self.client.get(
            f"/meetings/recordings/{self.completed.id}/file",
            headers={"Authorization": "Bearer host", "Range": "bytes=0-3"},
        )
        self.assertEqual(partial.status_code, 206)
        self.assertEqual(partial.content, b"0123")
        self.assertEqual(partial.headers["content-range"], "bytes 0-3/10")

        by_query = self.client.get(f"/meetings/recordings/{self.completed.id}/file?token=host")
        self.assertEqual(by_query.status_code, 200)

        self.db.add(RetentionPolicy(auto_delete_days=1))
        self.completed.ended_at = datetime.now(timezone.utc) - timedelta(days=3)
        self.db.commit()
        expired = self.client.get(
            f"/meetings/recordings/{self.completed.id}/file",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(expired.status_code, 410)
        self.assertEqual(expired.json()["detail"], "This recording has expired")

        mine = self.client.get("/meetings/recordings/mine", headers={"Authorization": "Bearer host"})
        self.assertEqual(mine.status_code, 200)
        ids = [item["recording_id"] for item in mine.json()["recordings"]]
        self.assertIn(self.completed.id, ids)
        self.holder["token"] = "stranger"
        hidden = self.client.get("/meetings/recordings/mine")
        self.assertEqual(hidden.json()["recordings"], [])


if __name__ == "__main__":
    unittest.main()
