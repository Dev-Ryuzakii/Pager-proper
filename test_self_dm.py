"""Self chat, recording cards, and the recording file route. SQLite, no Postgres."""

import asyncio
import base64
import json
import logging
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    LinkedDevice,
    Meeting,
    MeetingRecording,
    Message,
    Organization,
    RetentionPolicy,
    User,
)


def _device_key(db, user, label):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    db.add(LinkedDevice(
        user_id=user.id, device_uuid=label, platform="desktop",
        public_key=base64.b64encode(spki).decode(),
    ))
    db.commit()
    return private


def _decrypt_card(private, message, device_uuid):
    wrapped = json.loads(message.encrypted_key)[device_uuid]
    aes_key = private.decrypt(
        base64.b64decode(wrapped),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plain = AESGCM(aes_key).decrypt(
        base64.b64decode(message.iv), base64.b64decode(message.encrypted_content), None,
    )
    return json.loads(plain)


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
        self.keys = {name: _device_key(self.db, self.users[name], f"dev-{name}") for name in ("me", "sam")}
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
        owner = "me" if first[0].recipient_id == self.users["me"].id else "sam"
        card = _decrypt_card(self.keys[owner], first[0], f"dev-{owner}")
        self.assertNotIn("Weekly sync", first[0].encrypted_content)
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
        owner = "me" if created[0].recipient_id == self.users["me"].id else "sam"
        card = _decrypt_card(self.keys[owner], created[0], f"dev-{owner}")
        self.assertNotIn("Weekly sync", created[0].encrypted_content)
        self.assertEqual(card["kind"], "meeting_notes")
        self.assertEqual(len(card["summary"]), 400)
        self.assertEqual(card["key_points"], ["a", "b", "c", "d", "e"])
        self.assertEqual(card["action_item_count"], 4)
        self.assertEqual(created[0].content_type, "meeting_notes")
        self.assertEqual(created[0].decoy_content, "📝 Meeting notes")
        recording.notes_json = json.dumps({"summary": "rewritten later", "key_points": [], "action_items": []})
        self.db.commit()
        self.assertEqual(self_dm.deliver_notes_cards(self.db, recording.id), [])


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
        self_dm.install_recording_library_routes(
            app, current_user, resolve, get_db, lambda: self.tmp.name, lambda: "test-secret",
        )
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
        self.assertEqual(by_query.status_code, 401)

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

    def test_processing_missing_file_is_not_expired(self):
        self.processing.status = "processing"
        self.processing.ended_at = datetime.now(timezone.utc) - timedelta(days=3)
        self.db.add(RetentionPolicy(auto_delete_days=1))
        self.db.commit()
        response = self.client.get(
            f"/meetings/recordings/{self.processing.id}/file",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(response.status_code, 409)
        self.assertNotEqual(response.status_code, 410)

    def test_file_link_sig_is_scoped_and_expiring(self):
        link = self.client.post(
            f"/meetings/recordings/{self.completed.id}/file-link",
            headers={"Authorization": "Bearer host"},
        )
        self.assertEqual(link.status_code, 200)
        body = self.client.get(link.json()["url"])
        self.assertEqual(body.status_code, 200)
        self.assertEqual(body.content, b"0123456789")

        ranged = self.client.get(link.json()["url"], headers={"Range": "bytes=0-3"})
        self.assertEqual(ranged.status_code, 206)
        self.assertEqual(ranged.content, b"0123")

        expired = self_dm.make_file_sig("test-secret", self.completed.id, self.users["host"].id, int(datetime.now(timezone.utc).timestamp()) - 5)
        stale = self.client.get(f"/meetings/recordings/{self.completed.id}/file?sig={expired}")
        self.assertEqual(stale.status_code, 401)

        other = self_dm.make_file_sig("test-secret", self.completed.id, self.users["host"].id, int(datetime.now(timezone.utc).timestamp()) + 600)
        mismatch = self.client.get(f"/meetings/recordings/{self.processing.id}/file?sig={other}")
        self.assertEqual(mismatch.status_code, 403)


class RecordingLifecycleTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.db = sessionmaker(bind=engine)()
        self.tmp = tempfile.TemporaryDirectory()
        self.org = Organization(name="Acme", slug="acme-life", contact_name="A", contact_email="a@life.test", auto_meeting_notes=True)
        self.db.add(self.org)
        self.db.flush()
        self.me = User(username="me", phone_number="+16660000001", organization_id=self.org.id, is_active=True)
        self.bare = User(username="bare", phone_number="+16660000002", organization_id=self.org.id, is_active=True)
        self.admin = User(username="boss", phone_number="+16660000003", organization_id=self.org.id, is_active=True, is_admin=True)
        self.db.add_all([self.me, self.bare, self.admin])
        self.db.flush()
        self.key = _device_key(self.db, self.me, "dev-me")
        self.conference = ConferenceSession(created_by_user_id=self.me.id, kind="meeting", is_active=True)
        self.db.add(self.conference)
        self.db.flush()
        self.db.add(ConferenceParticipant(
            conference_id=self.conference.id, user_id=self.me.id, status="admitted", is_active=True,
        ))
        self.db.add(ConferenceParticipant(
            conference_id=self.conference.id, user_id=self.bare.id, status="admitted", is_active=False, left_at=datetime(2026, 11, 17, 10, 1),
        ))
        self.db.add(Meeting(
            creator_id=self.me.id, title="Weekly sync", scheduled_at=datetime(2026, 11, 17, 10, 0),
            join_code="life1", conference_id=self.conference.id,
        ))
        self.path = os.path.join(self.tmp.name, "ready.mp4")
        with open(self.path, "wb") as handle:
            handle.write(b"0123456789")
        self.recording = MeetingRecording(
            conference_id=self.conference.id, started_by_user_id=self.me.id, egress_id="eg-life",
            status="recording", file_path=self.path, started_at=datetime(2026, 11, 17, 10, 0),
        )
        self.db.add(self.recording)
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _client(self):
        def get_db():
            yield self.db

        app = FastAPI()
        self_dm.install_livekit_webhook_route(app, get_db, "key", "secret", lambda: self.tmp.name)
        return TestClient(app)

    def _post(self, client, payload, auth=None):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/webhook+json"}
        if auth is not False:
            headers["Authorization"] = auth or self_dm.sign_livekit_webhook(body, "key", "secret")
        return client.post("/livekit/webhook", content=body, headers=headers)

    def test_egress_ended_completes_once(self):
        client = self._client()
        event = {"event": "egress_ended", "egressInfo": {"egressId": "eg-life", "status": "EGRESS_COMPLETE"}}
        first = self._post(client, event)
        self.assertEqual(first.status_code, 200)
        self.db.refresh(self.recording)
        self.assertEqual(self.recording.status, "completed")
        self.assertEqual(self.recording.file_size, 10)
        self.assertEqual(self.recording.ai_status, "processing")
        cards = self.db.query(Message).filter(Message.content_type == "meeting_recording").all()
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0].recipient_id, self.me.id)
        self.assertNotIn("Weekly sync", cards[0].encrypted_content)
        again = self._post(client, event)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(self.db.query(Message).filter(Message.content_type == "meeting_recording").count(), 1)
        self.assertEqual(self.recording.ai_status, "processing")

        missing = self._post(client, event, auth=False)
        self.assertEqual(missing.status_code, 401)
        bad = self._post(client, event, auth="not-a-jwt")
        self.assertEqual(bad.status_code, 401)

    def test_room_finished_ends_the_conference_and_marks_processing(self):
        client = self._client()
        response = self._post(client, {"event": "room_finished", "room": {"name": f"conf-{self.conference.id}"}})
        self.assertEqual(response.status_code, 200)
        self.db.refresh(self.conference)
        self.db.refresh(self.recording)
        self.assertFalse(self.conference.is_active)
        self.assertIsNotNone(self.conference.ended_at)
        self.assertEqual(self.recording.status, "processing")
        self.assertEqual(self.db.query(Message).count(), 0)

    def test_sweeper_completes_a_stable_file_and_fails_a_missing_one(self):
        now = datetime.now(timezone.utc)
        self.recording.status = "processing"
        self.recording.ended_at = now - timedelta(minutes=3)
        missing = MeetingRecording(
            conference_id=self.conference.id, started_by_user_id=self.me.id, egress_id="eg-gone",
            status="processing", file_path=os.path.join(self.tmp.name, "missing.mp4"),
            started_at=now - timedelta(minutes=40), ended_at=now - timedelta(minutes=31),
        )
        self.db.add(missing)
        self.db.commit()
        seen = {self.recording.id: (10, now - timedelta(seconds=90))}
        actions = self_dm.sweep_recordings(self.db, now, self.tmp.name, lambda _eid: None, lambda _cid: None, seen)
        self.db.refresh(self.recording)
        self.db.refresh(missing)
        self.assertEqual(self.recording.status, "completed")
        self.assertEqual(missing.status, "failed")
        self.assertIn("ready", [item["action"] for item in actions])
        self.assertIn("failed", [item["action"] for item in actions])

    def test_stop_and_leave_claim_the_row_once(self):
        stops = []

        async def stop(egress_id):
            stops.append(egress_id)

        async def both():
            return await asyncio.gather(
                self_dm.complete_live_recordings(self.db, self.conference.id, stop),
                self_dm.complete_live_recordings(self.db, self.conference.id, stop),
            )

        asyncio.run(both())
        self.db.refresh(self.recording)
        self.assertEqual(stops, ["eg-life"])
        self.assertEqual(self.recording.status, "processing")
        first = self_dm.finalize_recording(self.db, self.recording.id, self.tmp.name)
        second = self_dm.finalize_recording(self.db, self.recording.id, self.tmp.name)
        self.assertTrue(first["run_ai"])
        self.assertFalse(second["run_ai"])
        self.assertEqual(self.db.query(Message).filter(Message.content_type == "meeting_recording").count(), 1)

    def test_second_card_insert_is_already_delivered(self):
        payload = {"kind": "meeting_recording", "meeting_title": "Weekly sync"}
        first = self_dm._insert_self_card(self.db, self.me, payload, "meeting_recording", "🎥 Meeting recording", "rec:1:1")
        second = self_dm._insert_self_card(self.db, self.me, payload, "meeting_recording", "🎥 Meeting recording", "rec:1:1")
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(self.db.query(Message).filter(Message.message_hash == "rec:1:1").count(), 1)
        from sqlalchemy.exc import IntegrityError
        self.db.add(Message(
            sender_id=self.me.id, recipient_id=self.me.id, encrypted_content="x",
            message_hash="rec:1:1", timestamp=datetime(2026, 11, 17, 10, 0),
        ))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_card_round_trip_and_no_plaintext_without_a_key(self):
        packed = self_dm.encrypt_for_user(self.db, self.me, json.dumps({"meeting_title": "Weekly sync"}))
        ciphertext, _wrapped, _iv = packed
        self.assertNotIn("Weekly sync", ciphertext)
        message = self_dm._insert_self_card(
            self.db, self.me, {"meeting_title": "Weekly sync"}, "meeting_recording", "🎥 Meeting recording", "rec:9:9",
        )
        card = _decrypt_card(self.key, message, "dev-me")
        self.assertEqual(card["meeting_title"], "Weekly sync")
        skipped = self_dm._insert_self_card(
            self.db, self.bare, {"meeting_title": "Weekly sync"}, "meeting_recording", "🎥 Meeting recording", "rec:9:8",
        )
        self.assertIsNone(skipped)
        stored = self.db.query(Message).filter(Message.recipient_id == self.bare.id).all()
        self.assertEqual(stored, [])

    def test_admin_mine_excludes_meetings_they_were_not_in(self):
        listed = self_dm.my_recordings(self.db, self.admin)
        self.assertEqual(listed, [])
        own = self_dm.my_recordings(self.db, self.me)
        self.assertEqual([item["recording_id"] for item in own], [self.recording.id])

    def test_many_partners_keep_order_and_unread_counts(self):
        base = datetime(2026, 1, 1, 12, 0)
        names = []
        for index in range(20):
            person = User(
                username=f"p{index:02d}", phone_number=f"+1555{index:04d}",
                organization_id=self.org.id, is_active=True,
            )
            self.db.add(person)
            self.db.flush()
            names.append(person)
            for step in range(9):
                self.db.add(Message(
                    sender_id=self.me.id, recipient_id=person.id, encrypted_content="x",
                    content_type="encrypted", delivered=True, read=True,
                    timestamp=base + timedelta(minutes=index * 20 + step),
                ))
            self.db.add(Message(
                sender_id=person.id, recipient_id=self.me.id, encrypted_content="unread",
                content_type="encrypted", delivered=True, read=False,
                timestamp=base + timedelta(minutes=index * 20 + 10),
            ))
        self.db.commit()
        listed = self_dm.list_conversations(self.db, self.me)
        self.assertTrue(listed[0]["is_self"])
        partners = [item for item in listed if not item["is_self"]]
        self.assertEqual([item["partner_username"] for item in partners], [f"p{index:02d}" for index in range(19, -1, -1)])
        self.assertTrue(all(item["unread_count"] == 1 for item in partners))
        self.assertEqual(self.db.query(Message).count(), 200)

    def test_self_note_is_not_pushed_or_webhooked(self):
        note = self_dm.dm_fanout("me", "me", "encrypted")
        self.assertTrue(note["ws"]["is_self"])
        self.assertEqual(note["ws"]["content_type"], "encrypted")
        self.assertFalse(note["push"])
        self.assertFalse(note["webhook"])
        other = self_dm.dm_fanout("me", "sam", "encrypted")
        self.assertNotIn("is_self", other["ws"])
        self.assertTrue(other["push"])
        self.assertTrue(other["webhook"])

    def test_access_log_drops_the_file_query(self):
        record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, "%s", (), None)
        record.args = ("GET /meetings/recordings/4/file?sig=sekret HTTP/1.1",)
        self.assertTrue(self_dm.RedactRecordingQuery().filter(record))
        self.assertNotIn("sig", record.args[0])
        self.assertIn("/meetings/recordings/4/file", record.args[0])


if __name__ == "__main__":
    unittest.main()
