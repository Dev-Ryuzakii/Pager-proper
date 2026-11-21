"""Live meeting transcript: routes, broadcast secret, and the utterance cutter. SQLite, no LiveKit."""

import asyncio
import os
import unittest
from datetime import datetime, timedelta

import numpy as np
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import captions_worker
import live_captions
from database_models import Base, ConferenceParticipant, ConferenceSession, Organization, User


def tone(seconds: float, amp: float = 0.2) -> np.ndarray:
    t = np.arange(int(seconds * 16000)) / 16000
    return (np.sin(2 * np.pi * 220 * t) * amp * 32767).astype(np.int16)


def quiet(seconds: float) -> np.ndarray:
    return np.zeros(int(seconds * 16000), dtype=np.int16)


class SegmenterTests(unittest.TestCase):
    def feed_all(self, seg, chunks):
        now = datetime(2026, 11, 17, 10, 0, 0)
        out = []
        for chunk in chunks:
            # Feed in 100 ms pieces, the way frames arrive from LiveKit.
            for i in range(0, len(chunk), 1600):
                piece = chunk[i:i + 1600]
                now += timedelta(milliseconds=len(piece) / 16)
                out += seg.feed(piece, now)
        return out, now

    def test_two_sentences_with_a_pause_become_two_utterances(self):
        seg = captions_worker.Segmenter()
        utts, _ = self.feed_all(seg, [quiet(0.5), tone(1.5), quiet(1.0), tone(2.0), quiet(1.0)])
        self.assertEqual(len(utts), 2)
        self.assertAlmostEqual(len(utts[0].audio) / 16000, 1.5 + 0.2 + 0.7, delta=0.1)
        self.assertLess(utts[0].ended_at, utts[1].started_at)

    def test_short_noise_is_ignored_and_long_speech_is_split(self):
        seg = captions_worker.Segmenter()
        utts, _ = self.feed_all(seg, [tone(0.2), quiet(1.0)])
        self.assertEqual(utts, [])
        utts, _ = self.feed_all(seg, [tone(30.0)])
        self.assertGreaterEqual(len(utts), 2)
        self.assertTrue(all(len(u.audio) / 16000 <= 12.05 for u in utts))

    def test_flush_returns_speech_still_in_progress(self):
        seg = captions_worker.Segmenter()
        _, now = self.feed_all(seg, [tone(1.0)])
        self.assertIsNotNone(seg.flush(now))
        self.assertIsNone(seg.flush(now))

    def test_clean_text_drops_whisper_filler_on_short_clips(self):
        self.assertIsNone(captions_worker.clean_text(" Thank you. ", 1.0))
        self.assertEqual(captions_worker.clean_text("Thank you.", 6.0), "Thank you.")
        self.assertEqual(captions_worker.clean_text("  ship   it  ", 1.0), "ship it")
        self.assertIsNone(captions_worker.clean_text("   ", 3.0))


class LiveCaptionRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["CAPTIONS_ENABLED"] = "1"
        os.environ["CAPTIONS_WORKER_SECRET"] = "s3cret-for-tests"
        self.addCleanup(os.environ.pop, "CAPTIONS_ENABLED", None)
        self.addCleanup(os.environ.pop, "CAPTIONS_WORKER_SECRET", None)

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.db = Session()
        org = Organization(name="Acme", slug="acme-cap", contact_name="A", contact_email="a@acme.test")
        self.db.add(org)
        self.db.flush()
        self.users = {}
        for i, name in enumerate(("host", "guest", "waiting", "stranger")):
            u = User(username=name, phone_number=f"+1888{i:04d}", organization_id=org.id, is_active=True)
            self.db.add(u)
            self.db.flush()
            self.users[name] = u
        conf = ConferenceSession(created_by_user_id=self.users["host"].id, is_active=True)
        self.db.add(conf)
        self.db.flush()
        self.conf_id = conf.id
        self.db.add_all([
            ConferenceParticipant(conference_id=conf.id, user_id=self.users["host"].id, is_active=True, status="admitted"),
            ConferenceParticipant(conference_id=conf.id, user_id=self.users["guest"].id, is_active=True, status="admitted"),
            ConferenceParticipant(conference_id=conf.id, user_id=self.users["waiting"].id, is_active=False, status="waiting"),
        ])
        self.db.commit()

        self.sent = []
        self.me = {"user": self.users["host"]}

        async def send(uid, payload):
            self.sent.append((uid, payload))
            return True

        app = FastAPI()
        live_captions.install_live_caption_routes(
            app,
            lambda: self.me["user"],
            lambda: Session(),
            lambda db, cid: self.users["host"].id,
            send,
            lambda db, uid: db.query(User).filter(User.id == uid).first().username,
        )
        self.client = TestClient(app)
        self.Session = Session

    def as_user(self, name):
        self.me["user"] = self.users[name]

    def test_host_starts_and_everyone_in_the_room_is_told(self):
        res = self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["status"], "starting")
        self.assertEqual(res.json()["started_by"], "host")
        told = sorted(uid for uid, p in self.sent if p["type"] == "meeting_captions_state")
        self.assertEqual(told, sorted([self.users["host"].id, self.users["guest"].id]))
        # Starting twice keeps one session.
        self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        self.assertEqual(self.db.query(live_captions.MeetingCaptionSession).count(), 1)

    def test_host_picks_and_switches_the_language(self):
        url = f"/calls/conference/{self.conf_id}/captions/start"
        res = self.client.post(url, json={"language": "fr"})
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["language"], "fr")
        self.sent.clear()
        # While it runs, naming another language switches it and tells the room.
        res = self.client.post(url, json={"language": "auto"})
        self.assertEqual(res.json()["language"], "auto")
        self.assertTrue(any(p["type"] == "meeting_captions_state" and p["data"]["language"] == "auto" for _, p in self.sent))
        db = self.Session()
        row = db.query(live_captions.MeetingCaptionSession).first()
        self.assertIsNone(row.language)
        self.assertEqual(db.query(live_captions.MeetingCaptionSession).count(), 1)
        # A plain start (no body) leaves the language alone.
        self.client.post(url, json={"language": "yo"})
        self.client.post(url)
        db = self.Session()
        self.assertEqual(db.query(live_captions.MeetingCaptionSession).first().language, "yo")
        self.assertEqual(self.client.post(url, json={"language": "xx"}).status_code, 400)
        listed = self.client.get(f"/calls/conference/{self.conf_id}/captions").json()["languages"]
        self.assertEqual(listed[0]["code"], "auto")

    def test_only_the_host_can_start_or_stop(self):
        self.as_user("guest")
        self.assertEqual(self.client.post(f"/calls/conference/{self.conf_id}/captions/start").status_code, 403)
        self.assertEqual(self.client.post(f"/calls/conference/{self.conf_id}/captions/stop").status_code, 403)

    def test_disabled_server_says_so(self):
        os.environ["CAPTIONS_ENABLED"] = "0"
        res = self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        self.assertEqual(res.status_code, 503)
        self.assertIn("isn't available", res.json()["detail"])

    def test_stop_turns_it_off(self):
        self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        res = self.client.post(f"/calls/conference/{self.conf_id}/captions/stop")
        self.assertEqual(res.json()["enabled"], False)
        db = self.Session()
        self.assertEqual(db.query(live_captions.MeetingCaptionSession).first().status, "stopped")

    def test_transcript_is_for_admitted_people_only(self):
        self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        session = self.Session().query(live_captions.MeetingCaptionSession).first()
        db = self.Session()
        now = datetime(2026, 11, 17, 10, 0, 0)
        for i, text in enumerate(("Hello team", "Let's ship Friday")):
            db.add(live_captions.MeetingCaptionSegment(
                session_id=session.id, conference_id=self.conf_id, speaker_username="host", speaker_name="Host",
                text=text, started_at=now + timedelta(seconds=i * 3), ended_at=now + timedelta(seconds=i * 3 + 2),
            ))
        db.commit()

        self.as_user("guest")
        res = self.client.get(f"/calls/conference/{self.conf_id}/captions")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual([s["text"] for s in body["segments"]], ["Hello team", "Let's ship Friday"])
        self.assertTrue(body["segments"][0]["started_at"].endswith("Z"))
        after = self.client.get(f"/calls/conference/{self.conf_id}/captions?after_id={body['segments'][0]['id']}")
        self.assertEqual([s["text"] for s in after.json()["segments"]], ["Let's ship Friday"])

        for name in ("waiting", "stranger"):
            self.as_user(name)
            self.assertEqual(self.client.get(f"/calls/conference/{self.conf_id}/captions").status_code, 403)

    def test_broadcast_needs_the_worker_secret(self):
        self.client.post(f"/calls/conference/{self.conf_id}/captions/start")
        session = self.Session().query(live_captions.MeetingCaptionSession).first()
        db = self.Session()
        seg = live_captions.MeetingCaptionSegment(
            session_id=session.id, conference_id=self.conf_id, speaker_username="guest", speaker_name="Guest",
            text="Sounds good", started_at=datetime(2026, 11, 17), ended_at=datetime(2026, 11, 17, 0, 0, 2),
        )
        db.add(seg)
        db.commit()
        self.sent.clear()

        bad = self.client.post("/internal/captions/broadcast", json={"segment_id": seg.id})
        self.assertEqual(bad.status_code, 401)
        wrong = self.client.post("/internal/captions/broadcast", json={"segment_id": seg.id},
                                 headers={"X-Captions-Secret": "nope"})
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(self.sent, [])

        ok = self.client.post("/internal/captions/broadcast", json={"segment_id": seg.id},
                              headers={"X-Captions-Secret": "s3cret-for-tests"})
        self.assertEqual(ok.status_code, 200)
        captions = [p for _, p in self.sent if p["type"] == "meeting_caption"]
        self.assertEqual(len(captions), 2)  # host and guest, not the waiting person
        self.assertEqual(captions[0]["data"]["text"], "Sounds good")
        self.assertEqual(captions[0]["data"]["speaker_name"], "Guest")

    def test_broadcast_is_closed_when_no_secret_is_configured(self):
        os.environ["CAPTIONS_WORKER_SECRET"] = ""
        res = self.client.post("/internal/captions/broadcast", json={"segment_id": 1},
                               headers={"X-Captions-Secret": ""})
        self.assertEqual(res.status_code, 503)


if __name__ == "__main__":
    unittest.main()
