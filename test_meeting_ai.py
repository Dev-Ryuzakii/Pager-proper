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


def test_paid_providers_refuse_without_keys():
    meeting_ai.DEEPGRAM_API_KEY = ""
    assert meeting_ai._transcribe_deepgram("/x") is None
    meeting_ai.ANTHROPIC_API_KEY = ""
    assert asyncio.run(meeting_ai._llm("s", "u", "claude")) is None


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
