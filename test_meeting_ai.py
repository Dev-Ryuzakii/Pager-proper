"""Offline tests for meeting_ai: no model, network or DB needed."""
import asyncio
import json
import os
import tempfile

import meeting_ai

GOOD = {
    "summary": "Team agreed to ship Friday.",
    "key_points": ["Ship Friday", ""],
    "decisions": ["Use local Whisper"],
    "action_items": [
        {"task": "Write migration", "owner": "Sam", "due": "Thu"},
        {"task": "  ", "owner": "x"},
        {"task": "Test it"},
    ],
}


def test_parse_notes_normalises():
    n = meeting_ai._parse_notes(json.dumps(GOOD))
    assert n["key_points"] == ["Ship Friday"]
    assert [a["task"] for a in n["action_items"]] == ["Write migration", "Test it"]
    assert n["action_items"][1] == {"task": "Test it", "owner": "", "due": ""}


def test_parse_notes_fenced_and_garbage():
    assert meeting_ai._parse_notes("```json\n" + json.dumps(GOOD) + "\n```")["summary"]
    assert meeting_ai._parse_notes("Sure! " + json.dumps(GOOD) + " done")["summary"]
    assert meeting_ai._parse_notes("not json") is None
    assert meeting_ai._parse_notes(None) is None
    assert meeting_ai._parse_notes("[1,2]") is None


def test_chunks_no_word_cut_and_lossless():
    text = " ".join(f"word{i}" for i in range(5000))
    parts = meeting_ai._chunks(text, 1000)
    assert len(parts) > 1 and all(len(p) <= 1000 for p in parts)
    assert " ".join(parts).split() == text.split()


def test_summarize_single_and_chunked(monkeypatch=None):
    calls = []

    async def fake_llm(system, user, provider):
        calls.append(system)
        return json.dumps(GOOD)

    orig = meeting_ai._llm
    meeting_ai._llm = fake_llm
    try:
        r = asyncio.run(meeting_ai.summarize_transcript("short talk"))
        assert r["summary"] and len(calls) == 1
        calls.clear()
        big = "word " * 10000  # 50k chars -> several chunks + 1 merge
        r = asyncio.run(meeting_ai.summarize_transcript(big))
        assert r["summary"] and len(calls) > 2 and calls[-1] == meeting_ai._MERGE_PROMPT
    finally:
        meeting_ai._llm = orig


def test_summarize_fails_cleanly():
    async def bad(system, user, provider):
        return "nope"

    orig = meeting_ai._llm
    meeting_ai._llm = bad
    try:
        assert asyncio.run(meeting_ai.summarize_transcript("hello")) is None
    finally:
        meeting_ai._llm = orig


def test_process_file_paths():
    r = asyncio.run(meeting_ai.process_file("/nonexistent.mp4"))
    assert r["status"] == "failed"

    async def fake_llm(system, user, provider):
        return json.dumps(GOOD)

    orig_llm, orig_tr = meeting_ai._llm, meeting_ai.transcribe_file
    meeting_ai._llm = fake_llm
    try:
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as f:
            f.write(b"x")
        meeting_ai.transcribe_file = lambda p, provider=None: None
        assert asyncio.run(meeting_ai.process_file(f.name))["status"] == "failed"
        meeting_ai.transcribe_file = lambda p, provider=None: "we met and decided things"
        r = asyncio.run(meeting_ai.process_file(f.name))
        assert r["status"] == "done" and r["transcript"] and r["notes"]["decisions"]
        os.remove(f.name)
    finally:
        meeting_ai._llm, meeting_ai.transcribe_file = orig_llm, orig_tr


def test_segments_group_speakers_and_local_tier_has_none():
    words = [
        {"word": "Hello", "punctuated_word": "Hello", "speaker": 0, "start": 0.1, "end": 0.4},
        {"word": "team", "punctuated_word": "team.", "speaker": 0, "start": 0.4, "end": 0.8},
        {"word": "Agreed", "punctuated_word": "Agreed", "speaker": 1, "start": 1.0, "end": 1.4},
    ]
    segments = meeting_ai.segments_from_words(words)
    assert segments[0]["speaker"] == "Speaker 1"
    assert segments[0]["text"] == "Hello team."
    assert segments[1]["speaker"] == "Speaker 2"
    assert segments[1]["start"] == 1.0
    assert meeting_ai.segments_from_words(None) == []


def test_denied_callers_are_not_revived():
    from conference_access import can_revive_original_caller
    assert can_revive_original_caller("call", "left") is True
    assert can_revive_original_caller("call", None) is True
    assert can_revive_original_caller("call", "denied") is False
    assert can_revive_original_caller("call", "removed") is False
    assert can_revive_original_caller("meeting", "left") is False


def test_notes_access_rules_and_share_text():
    import meeting_notes
    assert meeting_notes.start_block("recording", None)[0] == 409
    assert meeting_notes.start_block("completed", "processing")[0] == 409
    assert meeting_notes.start_block("completed", None) is None
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    assert meeting_notes.processing_is_stale("processing", now - timedelta(hours=3), now) is True
    assert meeting_notes.processing_is_stale("processing", now - timedelta(minutes=5), now) is False
    assert meeting_notes.start_block("completed", "processing", now - timedelta(hours=3), now) is None
    stuck = type("R", (), {"ai_status": "processing", "ai_started_at": None, "ai_error": None})()
    assert meeting_notes.fail_stale_jobs([stuck], now) == 1
    assert stuck.ai_status == "failed"
    assert meeting_notes.rerun_block("done", False, False)[0] == 403
    assert meeting_notes.rerun_block("done", True, False) is None
    assert meeting_notes.rerun_block("failed", False, False) is None
    assert meeting_notes.rate_limit_block([now, now], now, 2, 3600) is True
    assert meeting_notes.rate_limit_block([now], now, 2, 3600) is False
    import meeting_ai
    assert meeting_ai.concurrency_limit("1") == 1
    assert meeting_ai.concurrency_limit("0") == 1
    assert meeting_ai.concurrency_limit("nope") == 1
    assert meeting_ai.resolve_recording_path("room.mp4", "/var/recordings") == "/var/recordings/room.mp4"
    assert meeting_ai.resolve_recording_path("/tmp/room.mp4", "/var/recordings") == "/tmp/room.mp4"
    assert meeting_ai.resolve_recording_path("", "/var/recordings") == ""
    assert meeting_notes.start_block("completed", "done") is None
    people = [
        {"id": 1, "username": "sam", "full_name": "Sam Lee"},
        {"id": 2, "username": "sam", "full_name": "Other"},
    ]
    assert meeting_notes.match_assignee("Sam Lee", people) == 1
    assert meeting_notes.match_assignee("sam", people) is None
    assert meeting_notes.match_assignee("", people) is None
    text = meeting_notes.share_markdown({
        "summary": "Shipped.",
        "key_points": ["Friday"],
        "decisions": [],
        "action_items": [{"task": "Write tests", "owner": "Sam", "due": "Thu"}],
    })
    assert "Shipped." in text and "Write tests" in text and "Sam" in text
    assert meeting_notes.share_markdown(None) == ""
    assert "conference 9" in meeting_notes.consent_audit_text(9)
    assert meeting_notes.recording_banner(False) == {}
    assert meeting_notes.recording_banner(True)["banner"] == "Recording and transcribing"
    assert meeting_notes.participant_was_admitted("admitted", True, None) is True
    assert meeting_notes.participant_was_admitted("admitted", False, "left") is True
    assert meeting_notes.participant_was_admitted("waiting", True, None) is False
    assert meeting_notes.participant_was_admitted("denied", False, None) is False
    assert meeting_notes.participant_was_admitted("admitted", False, None) is False
    assert meeting_notes.can_assign_others(False, True, False, None) is True
    assert meeting_notes.can_assign_others(False, True, False, 4) is False
    assert meeting_notes.can_assign_others(False, False, True, 4) is True
    assert meeting_notes.assignee_for_action(False, 9, 3) is None
    assert meeting_notes.assignee_for_action(False, 3, 3) == 3
    assert meeting_notes.assignee_for_action(True, 9, 3) == 9


def test_diarized_call_returns_none_on_error():
    meeting_ai.DEEPGRAM_API_KEY = "present"
    text, segments = meeting_ai._transcribe_deepgram_diarized("/no/such/recording.mp4")
    assert text is None and segments is None
    meeting_ai.DEEPGRAM_API_KEY = ""


def test_paid_providers_refuse_without_keys():
    meeting_ai.DEEPGRAM_API_KEY = ""
    assert meeting_ai._transcribe_deepgram("/x") is None
    meeting_ai.ANTHROPIC_API_KEY = ""
    assert asyncio.run(meeting_ai._llm("s", "u", "claude")) is None


def test_meeting_notes_endpoint_permissions():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import meeting_notes
    from database_models import Base, ConferenceParticipant, ConferenceSession, MeetingRecording, Organization, User

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    org = Organization(name="Notes Org", slug="notes-org", contact_name="N", contact_email="n@notes.test")
    db.add(org)
    db.flush()
    people = {}
    for name, admin in (
        ("host", False), ("guest", False), ("other", False), ("admin", True),
        ("waiting", False), ("denied", False), ("invited", False),
    ):
        user = User(
            username=name, phone_number=f"+1666{len(people):04d}",
            organization_id=org.id, is_admin=admin, is_active=True,
        )
        db.add(user)
        db.flush()
        people[name] = user
    conference = ConferenceSession(created_by_user_id=people["host"].id, kind="meeting")
    db.add(conference)
    db.flush()
    db.add(ConferenceParticipant(conference_id=conference.id, user_id=people["host"].id, status="admitted", is_active=True))
    db.add(ConferenceParticipant(conference_id=conference.id, user_id=people["guest"].id, status="admitted", is_active=True))
    db.add(ConferenceParticipant(conference_id=conference.id, user_id=people["waiting"].id, status="waiting", is_active=True))
    db.add(ConferenceParticipant(conference_id=conference.id, user_id=people["denied"].id, status="denied", is_active=False))
    db.add(ConferenceParticipant(conference_id=conference.id, user_id=people["invited"].id, status="admitted", is_active=False, left_at=None))
    recording = MeetingRecording(
        conference_id=conference.id, started_by_user_id=people["host"].id,
        egress_id="eg-1", status="completed", file_path="/tmp/none.mp4",
    )
    db.add(recording)
    db.commit()
    holder = {"user": people["guest"]}
    started = []
    app = FastAPI()

    def current_user():
        return holder["user"]

    def get_db():
        yield db

    meeting_notes.install_meeting_notes_routes(
        app, current_user, get_db, lambda recording_id: started.append(recording_id),
        lambda *args: None,
    )
    client = TestClient(app)
    rid = recording.id
    assert client.get(f"/meetings/recordings/{rid}/notes").status_code == 200
    holder["user"] = people["other"]
    assert client.get(f"/meetings/recordings/{rid}/notes").status_code == 403
    for name in ("waiting", "denied", "invited"):
        holder["user"] = people[name]
        assert client.get(f"/meetings/recordings/{rid}/notes").status_code == 403, name
    assert client.post(f"/meetings/recordings/{rid}/notes").status_code == 403
    holder["user"] = people["admin"]
    first = client.post(f"/meetings/recordings/{rid}/notes")
    assert first.status_code == 202, first.text
    assert started == [rid]
    again = client.post(f"/meetings/recordings/{rid}/notes")
    assert again.status_code == 409
    recording.notes_json = '{"action_items":[{"task":"Write the recap","owner":"host"}]}'
    db.commit()
    recording.ai_status = "done"
    recording.ai_started_at = None
    db.commit()
    holder["user"] = people["guest"]
    denied_rerun = client.post(f"/meetings/recordings/{rid}/notes")
    assert denied_rerun.status_code == 403, denied_rerun.text
    holder["user"] = people["host"]
    host_rerun = client.post(f"/meetings/recordings/{rid}/notes")
    assert host_rerun.status_code == 202, host_rerun.text
    holder["user"] = people["guest"]
    created = client.post(f"/meetings/recordings/{rid}/notes/action-items/0/task")
    assert created.status_code == 201, created.text
    assert created.json()["assignee_id"] is None
    repeat = client.post(f"/meetings/recordings/{rid}/notes/action-items/0/task")
    assert repeat.status_code == 200, repeat.text
    assert repeat.json()["task_id"] == created.json()["task_id"]
    db.close()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
