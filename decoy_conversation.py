"""
Scripted cover conversations for decoy text.

Every conversation (a pair of people, a group or a meeting) gets its own
believable workplace storyline. Each day starts a fresh set of threads, each
thread runs in order (question, answer, follow-up, wrap-up), the same project
and client names carry through a thread, and a decoy already shown in that
conversation is never reused for another message.

Everything is deterministic from the conversation key, the day number and the
turn position, so two server workers produce the same line for the same turn,
and nothing extra has to be stored.
"""

import hashlib
import random
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set

# ── Vocabulary ────────────────────────────────────────────────────────────────

_PROJECTS = [
    "the Q3 budget review", "the vendor onboarding", "the CRM migration",
    "the compliance audit", "the payroll rollout", "the client portal",
    "the procurement plan", "the Lagos office move", "the risk assessment",
    "the quarterly forecast", "the data cleanup", "the policy update",
    "the training programme", "the network upgrade", "the brand refresh",
    "the board pack", "the recruitment drive", "the customer survey",
    "the contract renewal", "the inventory count", "the website relaunch",
    "the expense policy", "the service desk revamp", "the annual report",
]
_CLIENTS = [
    "Northwind", "Halden Group", "Crestline", "Meridian", "Oakridge",
    "Bluepeak", "Sterling & Co", "Arcadia", "Lumen Partners", "Kestrel",
    "Redwood Logistics", "Summit Health", "Triton Energy", "Vantage Retail",
]
_DOCS = [
    "the slide deck", "the cost sheet", "the draft memo", "the project plan",
    "the status report", "the meeting notes", "the proposal", "the tracker",
    "the scope document", "the risk register", "the invoice batch",
    "the handover note", "the summary", "the spreadsheet",
]
_TEAMS = [
    "finance", "operations", "legal", "HR", "procurement", "IT", "sales",
    "compliance", "client services", "admin", "audit", "marketing",
]
_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
_TIMES = ["10am", "11am", "11:30", "12pm", "1pm", "2pm", "2:30", "3pm", "4pm"]
_ROLES = ["the director", "my manager", "the client lead", "the auditor", "the project sponsor", "the team lead"]
_SECTIONS = ["the cost breakdown", "the timeline", "the appendix", "the summary page", "section three", "the assumptions tab"]

# ── Threads ───────────────────────────────────────────────────────────────────
# "turns" alternate speakers: even index is whoever opens the thread, odd index
# is the other person. "extra" lines are used when the same person sends again
# before the other side answers.

_THREADS: List[Dict[str, List[str]]] = [
    {
        "turns": [
            "Do you have the latest numbers for {project}",
            "Almost, {team} sent their figures this morning",
            "Great, can you drop them into {doc} when ready",
            "Will do, should be in there before {time}",
            "Perfect, I'll review once it's in",
        ],
        "extra": [
            "Mainly need {section} for now",
            "{role} asked for it before close of day",
            "No rush on the rest of it",
        ],
    },
    {
        "turns": [
            "Are we still on for the meeting on {project} at {time}",
            "Yes, I've booked the small conference room",
            "Good, I'll bring {doc}",
            "Can you also loop in someone from {team}",
            "Sure, I'll add them to the invite now",
            "Thanks, see you there",
        ],
        "extra": [
            "Might be five minutes late, wrapping up another call",
            "I'll share my screen for the first part",
        ],
    },
    {
        "turns": [
            "{client} came back on the proposal",
            "Oh nice, what did they say",
            "They're fine with scope but want to revisit pricing",
            "Expected that, let's look at {section} together",
            "Agreed, free around {time}",
            "Works for me",
        ],
        "extra": [
            "They also asked about delivery dates",
            "Forwarding their email to you now",
        ],
    },
    {
        "turns": [
            "Quick one, who's handling approvals for {project} this week",
            "I think it's still {role}",
            "Okay, I'll send {doc} to them directly",
            "Copy me in so I can track it",
            "Will do",
        ],
        "extra": [
            "Just want to avoid it sitting in the queue again",
            "Last time it took almost a week",
        ],
    },
    {
        "turns": [
            "Have you had a chance to look at {doc}",
            "Halfway through, a few comments on {section}",
            "No problem, leave them in the file and I'll update",
            "Done, mostly small wording changes",
            "Thanks, I'll send the revised version to {team}",
        ],
        "extra": [
            "Ignore the formatting for now, still cleaning it up",
            "Version two is in the shared folder",
        ],
    },
    {
        "turns": [
            "The {team} team is asking for an update on {project}",
            "We're on track, just waiting on sign off",
            "Can I tell them {day} for the final version",
            "{day} should be fine, maybe end of day",
            "Okay, I'll let them know",
        ],
        "extra": [
            "They seem a bit anxious about the timeline",
            "I'll keep it short in my reply",
        ],
    },
    {
        "turns": [
            "Did the invoices for {client} go out",
            "Not yet, finance flagged two line items",
            "What's the issue",
            "Duplicate charges on the last batch, they're checking",
            "Okay, keep me posted so I can update the client",
            "Will do, should be sorted by {time}",
        ],
        "extra": [
            "The client asked about it yesterday",
            "Let me know if you need the purchase order",
        ],
    },
    {
        "turns": [
            "Can you send me the agenda for {day}",
            "Sure, still finalising one item on {project}",
            "No rush, sometime this morning is fine",
            "Just sent it over",
            "Got it, thanks",
        ],
        "extra": [
            "Mostly need it to prep {doc}",
            "Add anything you think is missing",
        ],
    },
    {
        "turns": [
            "I'm getting an access error on the shared drive",
            "Same here since this morning",
            "Should we raise a ticket with IT",
            "Already did, they said it's a permissions issue",
            "Okay, I'll work locally until it's fixed",
        ],
        "extra": [
            "Can't open {doc} at all right now",
            "Hopefully it doesn't hold up {project}",
        ],
    },
    {
        "turns": [
            "Who's presenting {project} to {role} on {day}",
            "I was going to, unless you want to take it",
            "You go ahead, I'll cover questions on {section}",
            "Sounds good, let's do a run through before",
            "Sure, {time} works for me",
        ],
        "extra": [
            "I'll trim the deck a bit before then",
            "They usually ask about budget first",
        ],
    },
    {
        "turns": [
            "Just got off the call with {client}",
            "How did it go",
            "Positive overall, they want a revised timeline",
            "Okay, I'll update {doc} and share it",
            "Thanks, they'd like it by {day}",
            "Noted, will make it happen",
        ],
        "extra": [
            "They were happy with the last delivery",
            "I'll send a short recap email",
        ],
    },
    {
        "turns": [
            "Can you check {section} in {doc}",
            "Looking now",
            "Some of the totals don't match what {team} sent",
            "You're right, it's using last month's figures",
            "Can you fix it before it goes out",
            "Updating it now",
        ],
        "extra": [
            "Good catch by the way",
            "I'll double check the other tabs too",
        ],
    },
    {
        "turns": [
            "Reminder that the report for {project} is due {day}",
            "Thanks, I'm on track",
            "Great, let me know if you need input from {team}",
            "I might need their figures by tomorrow",
            "I'll give them a heads up",
        ],
        "extra": [
            "Same format as last quarter",
            "{role} wants a one page summary on top",
        ],
    },
    {
        "turns": [
            "Are you joining the {team} sync at {time}",
            "Yes, but I might drop off early",
            "No problem, I'll take notes",
            "Thanks, can you share them after",
            "Sure, I'll post them in here",
        ],
        "extra": [
            "Main item is {project}",
            "Should be a short one",
        ],
    },
    {
        "turns": [
            "The vendor sent a new quote for {project}",
            "Higher or lower than before",
            "About eight percent higher",
            "Hmm, we should push back on that",
            "Agreed, I'll ask procurement to negotiate",
            "Good, copy me on the email",
        ],
        "extra": [
            "They said material costs went up",
            "Their delivery date also moved",
        ],
    },
    {
        "turns": [
            "Can we move our check in to {time}",
            "Sure, something came up",
            "{role} called a last minute meeting",
            "No problem, {time} works",
            "Thanks, I'll update the invite",
        ],
        "extra": [
            "Shouldn't take more than half an hour",
            "Sorry for the short notice",
        ],
    },
    {
        "turns": [
            "Did legal sign off on the {client} contract",
            "Still with them, they had questions on the terms",
            "Anything major",
            "Mostly about the payment schedule",
            "Okay, let's discuss before replying to the client",
            "Sure, I'll set up a short call",
        ],
        "extra": [
            "I've attached their comments to {doc}",
            "They want it back by {day}",
        ],
    },
    {
        "turns": [
            "New hire starts on {day}, is their laptop ready",
            "IT said it'll be set up by tomorrow",
            "Great, can you also share the onboarding checklist",
            "Sending it now",
            "Thanks, I'll walk them through it on day one",
        ],
        "extra": [
            "They'll be joining the {team} team",
            "We should add them to the channel for {project} too",
        ],
    },
    {
        "turns": [
            "I've uploaded {doc} for {project}",
            "Thanks, I'll go through it this afternoon",
            "Mainly need your view on {section}",
            "Got it, I'll leave comments",
            "Appreciate it",
        ],
        "extra": [
            "It's the version with the updated figures",
            "Ignore the old file in the folder",
        ],
    },
    {
        "turns": [
            "How are we looking on {project}",
            "About seventy percent done",
            "Any blockers",
            "Waiting on input from {team}",
            "Want me to chase them",
            "That would help, thanks",
        ],
        "extra": [
            "Everything else is moving well",
            "Should be able to share a draft {day}",
        ],
    },
]

# Follow-ups when the same person sends again. The thread's own "extra" lines
# are written for whoever opened it; these cover both sides after that.
_OPENER_MORE = [
    "Let me know if anything is unclear",
    "Happy to jump on a call if easier",
    "I've noted it in {doc} as well",
    "{role} will want an update on this",
    "Just want to close this out before {day}",
    "I'll check back around {time}",
]
_REPLIER_MORE = [
    "Let me double check with {team} first",
    "I'll confirm once I hear back",
    "Give me a few minutes on this",
    "I'll update {doc} as well",
    "Will flag it if anything changes",
    "Should have more by {time}",
    "Just finishing something else first",
]

_DAY_OPENERS = [
    "Morning,", "Good morning,", "Hi,", "Hey,",
    "Following up from yesterday,", "Picking this back up,", "Quick one this morning,",
]
_GROUP_OPENERS = ["Morning all,", "Hi everyone,", "Morning team,", "Hi all,"]

# Last resort when every variation of a line was already shown in this
# conversation; combined with the line itself this keeps it unique.
_TAILS = [
    "will confirm by {time}", "updating {doc} too", "flagging for {team}",
    "noting it in {doc}", "will share by {day}", "copying {team} in",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _seed(*parts: Any) -> int:
    raw = "|".join(str(p) for p in parts).encode()
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text


def _fill(template: str, rng: random.Random, fixed: Mapping[str, str]) -> str:
    def pick(name: str) -> str:
        if name in fixed:
            return fixed[name]
        pool = {
            "doc": _DOCS, "team": _TEAMS, "day": _DAYS, "time": _TIMES,
            "role": _ROLES, "section": _SECTIONS, "client": _CLIENTS,
            "project": _PROJECTS,
        }.get(name)
        return rng.choice(pool) if pool else name
    out = re.sub(r"\{(\w+)\}", lambda m: pick(m.group(1)), template)
    return _cap(out)


def _thread_order(conv_key: str, day_index: int) -> List[int]:
    order = list(range(len(_THREADS)))
    random.Random(_seed(conv_key, "order", day_index)).shuffle(order)
    return order


def _thread_vars(conv_key: str, day_index: int, thread_no: int) -> Dict[str, str]:
    """Names that stay fixed for a whole thread, drawn from the conversation's own set."""
    conv_rng = random.Random(_seed(conv_key, "cast"))
    own_projects = conv_rng.sample(_PROJECTS, 5)
    own_clients = conv_rng.sample(_CLIENTS, 3)
    own_teams = conv_rng.sample(_TEAMS, 4)
    rng = random.Random(_seed(conv_key, "vars", day_index, thread_no))
    return {
        "project": rng.choice(own_projects),
        "client": rng.choice(own_clients),
        "team": rng.choice(own_teams),
        "doc": rng.choice(_DOCS),
        "day": rng.choice(_DAYS),
        "time": rng.choice(_TIMES),
        "role": rng.choice(_ROLES),
        "section": rng.choice(_SECTIONS),
    }


def _position(today_senders: Sequence[Any], sender: Any) -> Dict[str, int]:
    """
    Where the next message sits in today's storyline.

    turn: how many times the speaker changed today (the next turn number when
    the sender differs from the last speaker). extra: how many messages in a
    row the current speaker has already sent past their turn.
    """
    turn = -1
    extra = 0
    last = object()
    for s in today_senders:
        if s != last:
            turn += 1
            extra = 0
            last = s
        else:
            extra += 1
    if sender != last:
        return {"turn": turn + 1, "extra": -1}
    return {"turn": max(turn, 0), "extra": extra}


def _locate(conv_key: str, day_index: int, turn: int) -> Dict[str, int]:
    """Map today's turn number onto (thread_no, index within that thread)."""
    order = _thread_order(conv_key, day_index)
    thread_no = 0
    remaining = turn
    while True:
        tpl = _THREADS[order[thread_no % len(order)]]
        n = len(tpl["turns"])
        if remaining < n:
            return {"thread_no": thread_no, "template": order[thread_no % len(order)], "idx": remaining}
        remaining -= n
        thread_no += 1


# ── Public ────────────────────────────────────────────────────────────────────

def next_line(
    conv_key: str,
    day_index: int,
    today_senders: Sequence[Any],
    sender: Any,
    used: Iterable[str] = (),
    is_group: bool = False,
) -> str:
    """The next line of this conversation's cover story, never one already used."""
    used_norm: Set[str] = {_norm(u) for u in used if u}
    pos = _position(today_senders, sender)
    loc = _locate(conv_key, day_index, pos["turn"])
    tpl = _THREADS[loc["template"]]
    fixed = _thread_vars(conv_key, day_index, loc["thread_no"])

    if pos["extra"] >= 0:
        # Same person again before the other side answered: add to their own
        # point, from their side of the thread.
        opener_side = loc["idx"] % 2 == 0
        generic = list(_OPENER_MORE if opener_side else _REPLIER_MORE)
        random.Random(_seed(conv_key, "more", day_index, loc["thread_no"], loc["idx"])).shuffle(generic)
        extras = (list(tpl["extra"]) if opener_side else []) + generic
        start = pos["extra"] % len(extras)
        bases = extras[start:] + extras[:start]
    else:
        bases = [tpl["turns"][loc["idx"]]]

    def build(variant: int, base: str) -> str:
        rng = random.Random(_seed(conv_key, day_index, loc["thread_no"], loc["idx"], pos["extra"], variant))
        # Variants past the first may re-pick the free names (doc, time...) but
        # keep the thread's project and client so the story stays consistent.
        vars_ = dict(fixed) if variant == 0 else {k: fixed[k] for k in ("project", "client")}
        text = _fill(base, rng, vars_)
        first_of_day = pos["turn"] == 0 and pos["extra"] < 0 and not today_senders
        if first_of_day:
            openers = _GROUP_OPENERS if is_group else _DAY_OPENERS
            if day_index == 0:
                openers = [o for o in openers if "yesterday" not in o and "back up" not in o]
            opener = rng.choice(openers)
            text = f"{opener} {text[:1].lower()}{text[1:]}"
        if variant >= 6:
            tail = _fill(rng.choice(_TAILS), rng, fixed)
            text = f"{text}, {tail[:1].lower()}{tail[1:]}"
        return text

    # Plain wording first (each follow-up line in turn), then re-picked names,
    # and only then a short tail; whatever is chosen is new to this conversation.
    for lo, hi in ((0, 1), (1, 6), (6, 24)):
        for base in bases:
            for variant in range(lo, hi):
                text = build(variant, base)
                if _norm(text) not in used_norm:
                    return text
    # Practically unreachable; still unique because of the counter.
    return f"{build(0, bases[0])} ({len(used_norm) + 1})"


def planned_line(context: Mapping[str, Any]) -> Optional[str]:
    """next_line() driven by the context dict the backend builds, or None if it lacks state."""
    state = context.get("story")
    if not isinstance(state, Mapping) or not state.get("conv_key"):
        return None
    return next_line(
        conv_key=str(state["conv_key"]),
        day_index=int(state.get("day_index") or 0),
        today_senders=list(state.get("today_senders") or []),
        sender=state.get("sender"),
        used=state.get("used") or [],
        is_group=bool(state.get("is_group")),
    )


def is_used(text: str, context: Mapping[str, Any]) -> bool:
    state = context.get("story")
    if not isinstance(state, Mapping):
        return False
    target = _norm(text)
    return any(_norm(u) == target for u in (state.get("used") or []) if u)
