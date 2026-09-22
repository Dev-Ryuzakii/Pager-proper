"""
Markov chain language model for realistic casual chat decoy text.
Self-contained by default - no external APIs or model files needed.

Optionally backed by a local LLM (Ollama on 127.0.0.1) for more varied decoys.
Enable with DECOY_LLM=1. The LLM never runs on the message send path: a
background thread pre-generates into a pool, and callers pop from it. If the
pool is empty or the LLM is unreachable, generation silently falls back to the
Markov chain, so send latency is unchanged either way.
"""

import json
import os
import random
import re
import threading
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional

# ── Training corpus ────────────────────────────────────────────────────────────
# ~185 casual everyday English phrases across varied topics.
# Shared bigrams across sentences create branching that produces novel output.

_CORPUS: List[str] = [
    # Checking in / general work chat
    "hey are you free for a quick call",
    "hey are you around this afternoon",
    "are you free to jump on a call",
    "what are you working on right now",
    "what are you doing after the standup",
    "just wanted to check in on the project",
    "haven't heard back from you on this yet",
    "hope the deadline is still on track",
    "hope everything is going okay on your end",
    "quick update on where we're at",
    "let's sync up before end of day",
    "circling back on this before we forget",
    "been meaning to follow up on this",
    "how's the report coming along",
    "how's everything going with the client",
    "just checking in on the timeline",
    "haven't touched base properly in a while",
    "we should really sync on this soon",
    "feel like this keeps getting pushed back",
    "you good on the numbers for this",

    # Meetings / scheduling
    "are you coming to the standup tonight",
    "can we push the meeting to this afternoon",
    "I'll join the call around eight or so",
    "I'll send the invite in a bit",
    "let me know if that time works for you",
    "we should grab a quick sync this week",
    "are you free for a call Saturday morning",
    "want to review this together this evening",
    "I'm heading into a meeting in twenty minutes",
    "running a little late sorry joining soon",
    "should I bring the deck when I come",
    "where do you want to have the review",
    "let's try a different approach this time",
    "I booked the room for seven thirty",
    "what time are you thinking we start",
    "we could kick off early to beat the rush",
    "are you presenting or should I",
    "let me know what time you're ready",
    "I'll send you the meeting link in a bit",
    "can you make it by noon",
    "sometime next week might work better for me",
    "would Friday work or is that too late",
    "we could do Sunday if the deadline slips",
    "let's not leave it too long this time",
    "either Thursday or Friday works for me",
    "we could just knock it all out together",
    "I was thinking we could try a different vendor",
    "are you bringing the rest of the team",

    # Office life
    "just got out of a meeting completely drained",
    "the wifi has been terrible again today",
    "can you send that file on your way out",
    "the printer has been jamming all morning",
    "I put together too many slides want to see",
    "my laptop battery is almost dead again",
    "I left my badge at the desk again",
    "need to stop by IT on the way in",
    "it's freezing in the office today bring a jacket",
    "finally quiet after that whole rush this morning",
    "the schedule has been so unpredictable lately",
    "can't focus it's way too loud in here tonight",
    "got in really early today couldn't sleep",
    "been running around all day need a break",
    "finally finished everything on my list today",
    "facilities came by to fix the AC",
    "spent all morning sorting out the onboarding docs",
    "the server was down again this morning",
    "I've been so slammed this whole week",
    "need to sort out so many tickets today",
    "forgot to set my reminder again this morning",
    "managed to clear my inbox before noon",
    "I have a review this afternoon",
    "have to pick up the new hire from reception",
    "the shipment was delayed again apparently",
    "the office next door is so loud today",
    "just finished a really long call outside",
    "stayed way too late working last night",
    "had the weirdest bug last night",
    "been trying to sort this out all day",

    # Coffee / lunch breaks
    "did you grab lunch yet today",
    "I'm starving haven't eaten since morning",
    "tried that new place near the office",
    "the food there was actually really good",
    "been craving coffee all morning honestly",
    "let's just order in today I'm too swamped",
    "are you grabbing lunch or should we order",
    "I burned the coffee again somehow",
    "grabbed a quick bite it actually helped",
    "you have to try the new cafe downstairs",
    "the portions there were huge we couldn't finish",
    "found this amazing little spot near work",
    "lunch break was surprisingly good today actually",
    "need to stop working through lunch again",
    "made too much coffee again as usual",
    "the cafe near the office has great pastries",
    "just had a quick bite honestly needed it",
    "should have eaten before this meeting",
    "I could really go for a coffee right now",
    "thinking about grabbing a proper lunch today",
    "we went to that place you recommended",
    "they changed the menu and it's better now",

    # Projects / deadlines
    "had back to back meetings all morning long",
    "that presentation actually went really well",
    "boss needs the report done by tomorrow",
    "have so much work piled up right now",
    "finally finished that deliverable late last night",
    "the client call felt like it went okay",
    "got the assignment done earlier than expected",
    "the review got cancelled again this week",
    "the deadline got pushed to Friday thankfully",
    "the team is meeting to go over the roadmap",
    "working late again tonight unfortunately",
    "the client moved the call to next week",
    "meeting ran over by almost an hour",
    "waiting to hear back about the proposal",
    "just submitted everything before the deadline",
    "the new system keeps crashing for everyone",
    "training session ran all afternoon today",
    "been on calls since early this morning",
    "so much admin to get through today",
    "finally got some feedback on that project",
    "they want revisions done by end of week",
    "things at work have been pretty hectic",
    "the ticket is still stuck in review",
    "can you approve this before end of day",
    "the numbers look good for this quarter",
    "we're still waiting on sign off from legal",
    "the client wants a status update by tomorrow",
    "just pushed the fix let me know if it holds",
    "the deck needs one more pass before the call",
    "finance flagged something we need to look at",

    # Casual observations
    "saw something ridiculous in the meeting today",
    "can you believe what actually happened in standup",
    "that was honestly so unexpected",
    "things are finally starting to calm down",
    "been meaning to reply to that thread for days",
    "time just flies by so fast on deadline weeks",
    "feels like we never have enough time",
    "this week has been completely exhausting",
    "really looking forward to the weekend finally",
    "almost forgot to mention this earlier",
    "by the way did you see that email",
    "good call I wouldn't have thought of that",
    "makes sense when you explain it like that",
    "totally forgot that meeting was even happening today",
    "keep meaning to sort that ticket out properly",
    "I keep putting it off and I really shouldn't",
    "this has been going on for weeks now",
    "thought it would be simple but it wasn't",
    "turns out it was easier than expected",
    "ended up being a whole thing today",
    "wasn't expecting that at all honestly",
    "so much going on at once right now",
    "thought I had more time than I actually did",
    "can't believe it's already end of quarter",
    "didn't realise how late the meeting ran",
    "finally got a moment to breathe today",

    # Short conversational replies
    "sounds good let me know",
    "okay I'll check and let you know",
    "on my way should be there soon",
    "give me about ten minutes",
    "okay see you on the call then",
    "got it I'll sort it out",
    "no problem at all don't worry about it",
    "let me check and I'll get back to you",
    "that works perfectly for me",
    "I'll figure something out don't stress",
    "sure just tell me when you're ready",
    "I'll handle it you don't need to worry",
    "we can figure out the rest later",
    "seriously though that meeting was rough",
    "I couldn't believe that the whole time",
    "never mind I worked it out",
    "actually that's a really good point",
    "fair enough that makes sense to me",
    "true I didn't think about it that way",
    "yeah no that's completely fair",
    "I was just about to say that",
    "that's exactly what I was thinking",

    # Tools / IT
    "have you tried the new dashboard yet",
    "the last update broke something again",
    "can't stop getting notifications from that channel",
    "you really have to read this doc",
    "that walkthrough was actually really helpful",
    "they just announced the new policy this morning",
    "the update broke everything again as usual",
    "my laptop has been running so slowly",
    "finally got it working after trying forever",
    "you should try that tool it's so useful",
    "the demo was incredible yesterday",
    "they just rolled out the new release",
    "everyone's been talking about the outage today",
    "worth checking out if you get the chance",
    "heard really good things about it recently",
    "the next release is supposed to be even better",

    # Business travel
    "just got back from the conference yesterday",
    "the venue there was absolutely incredible",
    "thinking about a short trip for the client visit",
    "need a break from all this travel honestly",
    "the flight took ages but was worth it",
    "found a great spot for the offsite",
    "should have packed lighter for the trip",
    "already planning the next site visit actually",
    "the whole event was just well organised",
    "want to go back for the next conference",
    "we toured the facility for hours it was worth it",
    "the office there was beautiful honestly",
]

# ── Markov chain ───────────────────────────────────────────────────────────────

class _MarkovChain:
    """Bigram Markov chain trained on _CORPUS."""

    def __init__(self, corpus: List[str], n: int = 2):
        self._n = n
        self._chain: Dict[Tuple, List[str]] = defaultdict(list)
        self._starters: List[Tuple] = []
        for sentence in corpus:
            tokens = sentence.lower().split()
            if len(tokens) <= n:
                continue
            self._starters.append(tuple(tokens[:n]))
            for i in range(len(tokens) - n):
                key = tuple(tokens[i : i + n])
                self._chain[key].append(tokens[i + n])

    def generate(self, min_words: int = 5, max_words: int = 14) -> str:
        for _ in range(30):
            state = random.choice(self._starters)
            words = list(state)
            for _ in range(max_words - self._n):
                nexts = self._chain.get(state)
                if not nexts:
                    break
                nxt = random.choice(nexts)
                words.append(nxt)
                state = tuple(words[-self._n :])
            if len(words) >= min_words:
                text = " ".join(words)
                return text[0].upper() + text[1:]
        # Fallback: return a random corpus sentence
        return random.choice(_CORPUS).capitalize()


_MODEL: Optional[_MarkovChain] = None


def _model() -> _MarkovChain:
    global _MODEL
    if _MODEL is None:
        _MODEL = _MarkovChain(_CORPUS)
    return _MODEL


# ── Optional local LLM decoy pool ──────────────────────────────────────────────
# Off unless DECOY_LLM=1. Runs entirely on 127.0.0.1 - no decoy text ever leaves
# the host. Generation happens on a daemon thread; the send path only ever pops
# an already-finished string, so the LLM's ~10 tok/s cannot slow a message down.

# Read on first use, not at import: this module gets imported alongside others
# that call load_dotenv(), and reading at import time would silently depend on
# which one lands first.

def _cfg(name: str, default: str) -> str:
    return os.getenv(name, default)

_PROMPT = (
    "Write one short internal work chat message between coworkers at a company, "
    "5 to 13 words. Everyday office talk - project status, deadlines, meetings, "
    "approvals, reports, client calls, IT issues. Casual tone, like a real Slack "
    "or Teams message, not formal email. Output only the message. No quotes, "
    "no emoji, no explanation."
)

# The reasoning-model guard: qwen3 and friends emit <think> blocks that leak
# into plain output when Ollama's think parsing is off. Strip them defensively
# so a model swap can never put "</think>" in a user-visible decoy.
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_STRAY = re.compile(r"</?think>", re.IGNORECASE)


def _clean(raw: str) -> Optional[str]:
    """Normalise raw model output into a decoy, or None if it is unusable."""
    text = _THINK_STRAY.sub(" ", _THINK_BLOCK.sub(" ", raw))
    text = text.replace("\n", " ").strip().strip('"').strip("'").strip()
    text = re.sub(r"\s+", " ", text)
    if not (10 <= len(text) <= 120):
        return None
    if len(text.split()) < 4:
        return None
    return text[0].upper() + text[1:]


def _llm_once(timeout: float) -> Optional[str]:
    """One streamed generation. Returns None on any failure - never raises."""
    try:
        import httpx  # lazy: the module stays importable without httpx installed
    except ImportError:
        return None

    payload = {
        "model": _cfg("DECOY_LLM_MODEL", "llama3.2:3b"),
        "prompt": _PROMPT,
        "stream": True,  # required: lets us drop the connection to free the slot
        "think": False,
        "options": {
            "num_predict": 48,   # token ceiling - the real bound on how long this runs
            "num_thread": int(_cfg("DECOY_LLM_THREADS", "6")),
            "num_ctx": 1024,
            "temperature": 1.0,  # decoys need variety more than coherence
        },
    }
    chunks: List[str] = []
    try:
        url = _cfg("DECOY_LLM_URL", "http://127.0.0.1:11434/api/generate")
        limits = httpx.Timeout(connect=2.0, read=timeout, write=2.0, pool=2.0)
        with httpx.Client(timeout=limits) as client:
            with client.stream("POST", url, json=payload) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    chunk = json.loads(line)
                    chunks.append(chunk.get("response", ""))
                    if chunk.get("done"):
                        break
    except Exception:
        # Exiting the context closes the socket, which makes Ollama release the
        # slot instead of burning CPU on a generation nobody is waiting for.
        return None
    return _clean("".join(chunks))


class _DecoyPool:
    """Bounded pool of pre-generated LLM decoys, refilled by a daemon thread."""

    def __init__(self, target: int):
        self._target = target
        self._items: Deque[str] = deque(maxlen=target)
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._started = False
        self._backoff = 1.0

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        threading.Thread(target=self._run, name="decoy-llm-pool", daemon=True).start()

    def pop(self) -> Optional[str]:
        with self._lock:
            item = self._items.popleft() if self._items else None
        if item is None or len(self._items) < self._target // 2:
            self._wake.set()
        return item

    def _run(self) -> None:
        while True:
            with self._lock:
                need = self._target - len(self._items)
            if need <= 0:
                self._wake.wait(timeout=60.0)
                self._wake.clear()
                continue

            text = _llm_once(float(_cfg("DECOY_LLM_TIMEOUT", "20")))
            if text is None:
                # Ollama down or model missing: back off so a dead service does
                # not spin this thread. The send path is unaffected regardless.
                self._wake.wait(timeout=self._backoff)
                self._wake.clear()
                self._backoff = min(self._backoff * 2, 300.0)
                continue

            self._backoff = 1.0
            with self._lock:
                self._items.append(text)


_POOL: Optional[_DecoyPool] = None


def _pool() -> Optional[_DecoyPool]:
    global _POOL
    if _cfg("DECOY_LLM", "0") != "1":
        return None
    if _POOL is None:
        _POOL = _DecoyPool(int(_cfg("DECOY_LLM_POOL", "64")))
        _POOL.start()
    return _POOL


def _decoy(min_words: int, max_words: int) -> str:
    """Pooled LLM decoy if one is ready, otherwise the Markov chain."""
    pool = _pool()
    if pool is not None:
        text = pool.pop()
        if text is not None:
            return text
    return _model().generate(min_words=min_words, max_words=max_words)


# ── Public interface (backward-compatible) ─────────────────────────────────────

class FakeTextGenerator:
    """
    Generates realistic casual chat decoy text using a Markov chain model.
    All methods keep their original signatures for drop-in compatibility.
    """

    @staticmethod
    def warm() -> bool:
        """
        Start the LLM decoy pool ahead of first use. Safe to call always: a
        no-op returning False when DECOY_LLM is unset. Call at app startup so
        the pool fills while idle rather than after the first message.
        """
        return _pool() is not None

    @staticmethod
    def generate_sentence() -> str:
        return _decoy(min_words=4, max_words=10)

    @staticmethod
    def generate_paragraph(sentence_count: int = 3) -> str:
        sentences = [_decoy(min_words=5, max_words=12) for _ in range(sentence_count)]
        return " ".join(sentences)

    @staticmethod
    def generate_message_preview(length: int = 50) -> str:
        text = _decoy(min_words=4, max_words=10)
        if len(text) <= length:
            return text
        cut = text[:length - 3].rsplit(" ", 1)[0]
        return cut + "..."

    @staticmethod
    def generate_decoy_text_for_message(encrypted_content: str) -> str:
        """Generate a unique, natural-sounding decoy for any message."""
        return _decoy(min_words=5, max_words=13)
