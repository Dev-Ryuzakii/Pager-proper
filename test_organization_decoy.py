"""Focused tests for organization-aware, work-only decoy generation."""

import fake_text_generator as generator
from fake_text_generator import FakeTextGenerator


def _context(last_text: str = ""):
    recent = [{"speaker": "coworker", "text": last_text}] if last_text else []
    return {
        "organization": "Northstar Logistics",
        "sender_department": "Operations",
        "recipient_department": "Finance",
        "conversation_type": "direct coworker conversation",
        "recent_messages": recent,
    }


def test_clean_rejects_affectionate_and_personal_output():
    assert generator._clean("I love you and miss you tonight") is None
    assert generator._clean("Would you like to have dinner this weekend") is None
    assert generator._clean("The finance report is ready for review") == "The finance report is ready for review"


def test_contextual_fallback_continues_the_work_topic(monkeypatch):
    monkeypatch.setenv("DECOY_LLM", "0")
    text = FakeTextGenerator.generate_decoy_text_for_message(
        "encrypted-content-is-never-used",
        context=_context("Can you confirm the project deadline"),
    )
    assert "deadline" in text.lower() or "timeline" in text.lower()
    assert generator._is_safe_work_text(text)


def test_context_prompt_reaches_ollama_without_encrypted_content(monkeypatch):
    captured = {}

    def fake_llm(timeout, prompt):
        captured["timeout"] = timeout
        captured["prompt"] = prompt
        return "I will update the finance report before the review"

    monkeypatch.setenv("DECOY_LLM", "1")
    monkeypatch.setattr(generator, "_llm_once", fake_llm)
    text = FakeTextGenerator.generate_decoy_text_for_message(
        "TOP-SECRET-CIPHERTEXT",
        context=_context("The finance report needs another review"),
    )

    assert text == "I will update the finance report before the review"
    assert "Northstar Logistics" in captured["prompt"]
    assert "Operations" in captured["prompt"]
    assert "The finance report needs another review" in captured["prompt"]
    assert "TOP-SECRET-CIPHERTEXT" not in captured["prompt"]


def test_markov_fallback_is_always_work_only(monkeypatch):
    monkeypatch.setenv("DECOY_LLM", "0")
    for _ in range(100):
        text = FakeTextGenerator.generate_sentence()
        assert generator._is_safe_work_text(text), text
