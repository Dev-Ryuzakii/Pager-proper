"""Dilarion AI: the dedicated AI page (conversations) and AI agents.

Conversations replace the old copilot widget: a history per user, one thread per
topic. When a message asks for work to be done, the reply carries a proposed
agent run.

An agent run takes an instruction ("remind Ada to send the budget Friday 9am and
put it on the org whiteboard"), asks the model for a plan made only of the tools
below, then executes the plan step by step with the caller's permissions. Runs
can wait for approval before acting. Every step and its result is stored so the
AI page can show what the agent did.

Tools (documents/sheets/slides come later):
  create_reminder        a reminder for yourself or, with permission, a colleague
  create_task            a task assigned to org members
  add_whiteboard_note    a sticky or task card on the org or a group whiteboard
  draft_meeting          a meeting draft the user confirms in the scheduler
  find_people            look up members of your organization
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String, Text, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

import reminders as reminders_mod
import whiteboards as wb_mod
from copilot_ollama import _ollama_generate
from database_models import Base, GroupMember, Task, TaskAssignee, User
from org_roles import has_permission, is_site_admin, resolve_org

logger = logging.getLogger(__name__)

MAX_STEPS = 8
TOOLS = {"create_reminder", "create_task", "add_whiteboard_note", "draft_meeting", "find_people"}


class AiConversation(Base):
    __tablename__ = "ai_conversations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(150), nullable=False, default="New chat")
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


class AiMessage(Base):
    __tablename__ = "ai_messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(10), nullable=False)  # user / assistant
    content = Column(Text, nullable=False)
    agent_run_id = Column(Integer, ForeignKey("ai_agent_runs.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now())


class AiAgentRun(Base):
    __tablename__ = "ai_agent_runs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True, index=True)
    # Who the work is for. Same as user_id unless sent on someone's behalf.
    for_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    conversation_id = Column(Integer, ForeignKey("ai_conversations.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(150), nullable=True)
    instruction = Column(Text, nullable=False)
    # planning / awaiting_approval / running / completed / failed / cancelled
    status = Column(String(20), nullable=False, default="planning", index=True)
    require_approval = Column(Integer, nullable=False, default=1)
    plan = Column(JSON, nullable=True)       # [{tool, args, why}]
    steps = Column(JSON, nullable=True)      # [{tool, args, status, result|error}]
    summary = Column(Text, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)


class AiPreference(Base):
    """Per-user AI settings. auto_approve = "full control": agents act without
    asking first (still limited to what the user's role allows)."""
    __tablename__ = "ai_preferences"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    auto_approve = Column(Boolean, nullable=False, default=False)
    # Added later, so nullable (schema_sync adds them without defaults); None = default.
    timezone = Column(String(64), nullable=True)            # IANA zone the apps report, e.g. Africa/Lagos
    allow_from_others = Column(Boolean, nullable=True)      # others' agents may set reminders / assign tasks to me
    disabled_tools = Column(JSON, nullable=True)            # tools agents may not use for me
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())


def auto_approve_enabled(db: Session, user_id: int) -> bool:
    row = db.get(AiPreference, int(user_id))
    return bool(row and row.auto_approve)


def _prefs(db: Session, user_id: int) -> "AiPreference":
    row = db.get(AiPreference, int(user_id))
    if row is None:
        row = AiPreference(user_id=int(user_id), auto_approve=False)
        db.add(row)
    return row


def prefs_dict(row: Optional["AiPreference"]) -> dict:
    return {
        "auto_approve": bool(row and row.auto_approve),
        "timezone": (row.timezone if row else None) or "UTC",
        "allow_from_others": True if not row or row.allow_from_others is None else bool(row.allow_from_others),
        "disabled_tools": [t for t in ((row.disabled_tools if row else None) or []) if t in TOOL_LABELS],
    }


def user_zone(db: Session, user_id: int) -> ZoneInfo:
    row = db.get(AiPreference, int(user_id))
    try:
        return ZoneInfo(row.timezone) if row and row.timezone else ZoneInfo("UTC")
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def remember_timezone(db: Session, user_id: int, request: Optional[Request]) -> None:
    """Keep the zone the app reports (X-Timezone) so times like "4pm" mean the user's 4pm."""
    tz = (request.headers.get("x-timezone") if request is not None else None) or ""
    tz = tz.strip()[:64]
    if not tz:
        return
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        return
    row = _prefs(db, user_id)
    if row.timezone != tz:
        row.timezone = tz
        db.commit()


def tool_disabled(db: Session, user_id: int, tool: str) -> bool:
    return tool in prefs_dict(db.get(AiPreference, int(user_id)))["disabled_tools"]


def accepts_from_others(db: Session, user_id: int) -> bool:
    return prefs_dict(db.get(AiPreference, int(user_id)))["allow_from_others"]


TOOL_LABELS = {
    "create_reminder": "Set reminders",
    "create_task": "Create and assign tasks",
    "add_whiteboard_note": "Add whiteboard notes",
    "draft_meeting": "Draft meetings",
    "find_people": "Find people",
}


def _iso(dt):
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def run_dict(r: AiAgentRun) -> dict:
    return {
        "id": r.id, "title": r.title, "instruction": r.instruction, "status": r.status,
        "for_user_id": r.for_user_id, "conversation_id": r.conversation_id,
        "require_approval": bool(r.require_approval), "plan": r.plan or [], "steps": r.steps or [],
        "summary": r.summary, "error": r.error, "created_at": _iso(r.created_at),
        "started_at": _iso(r.started_at), "finished_at": _iso(r.finished_at),
    }


def msg_dict(m: AiMessage) -> dict:
    return {"id": m.id, "role": m.role, "content": m.content, "agent_run_id": m.agent_run_id,
            "created_at": _iso(m.created_at)}


# ─── Prompts ──────────────────────────────────────────────────────────────────

_PLAN_PROMPT = """You are a Dilarion AI agent. You turn an instruction into a short plan using ONLY these tools:

create_reminder      {"title": str, "remind_at": local time, "for": username or "me", "note": str?, "recurrence": null|"daily"|"weekdays"|"weekly"|"monthly"}
create_task          {"title": str, "description": str?, "due_at": local time or null, "assignees": [username, ...]}
add_whiteboard_note  {"board": "org" or a group name, "text": str, "kind": "sticky"|"task", "color": str?}
draft_meeting        {"title": str, "scheduled_at": local time, "duration_minutes": int, "participants": [username, ...]}
find_people          {"query": str}

Respond with ONLY JSON: {"title": short title for the job, "steps": [{"tool": str, "args": {...}, "why": str}], "summary": one sentence describing the plan}
Rules: at most 8 steps. Use only people named in the instruction or in the provided member list.
Times: write every time as the user's LOCAL wall-clock time "YYYY-MM-DDTHH:MM" with NO timezone or "Z" ("4pm" -> "T16:00").
Resolve relative times against the current local time given, using the calendar provided: "Friday" means the date listed for Friday; "every Friday at 4pm" starts on the next Friday at 16:00 with recurrence "weekly". Never pick a time already in the past.
If the instruction cannot be done with these tools, return an empty steps list and explain in summary."""

_CHAT_PROMPT = """You are Dilarion AI, the assistant on the AI page of a secure team messaging app. You can chat, answer questions, and send agents to do work in the app: set reminders, create and assign tasks, add notes to whiteboards, draft meetings, find colleagues.

Respond with ONLY JSON: {"reply": str, "agent_instruction": str or null, "title": short title for this conversation}
Set agent_instruction to a complete, self-contained instruction ONLY when the user is asking you to do one of those actions; otherwise null. Keep the user's days and times exactly as they said them in agent_instruction ("every Friday at 4pm"), never convert them. Keep reply concise plain text."""


def _loads(raw: Optional[str]) -> Optional[dict]:
    if not raw:
        return None
    try:
        out = json.loads(raw)
        return out if isinstance(out, dict) else None
    except json.JSONDecodeError:
        return None


def _parse_dt(value: Any, zone: Optional[ZoneInfo] = None) -> Optional[datetime]:
    """ISO time -> UTC. A time without an offset is the user's local time."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=zone or timezone.utc)
    return dt.astimezone(timezone.utc)


_WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
_TIME_ARGS = ("remind_at", "due_at", "scheduled_at")


def time_context(zone: ZoneInfo) -> str:
    now = datetime.now(zone)
    days = "\n".join(f"- {(now + timedelta(days=i)):%A %Y-%m-%d}" + (" (today)" if i == 0 else "")
                     for i in range(8))
    return (f"Current local time: {now:%A %Y-%m-%d %H:%M} ({zone.key}, UTC{now:%z})\n"
            f"Calendar for the next days:\n{days}")


def normalize_plan_times(steps: list, instruction: str, zone: ZoneInfo) -> list:
    """Make plan times exact UTC, and keep them on the weekday the instruction names.

    Small models often ignore "Friday" and use today's date, or treat "4pm" as UTC.
    """
    text = (instruction or "").lower()
    named = [i for i, d in enumerate(_WEEKDAYS) if re.search(rf"\b{d}s?\b", text)]
    now = datetime.now(timezone.utc)
    for step in steps:
        args = step.get("args") or {}
        for key in _TIME_ARGS:
            if not args.get(key):
                continue
            # The model is told to write local wall-clock time; it sometimes adds a
            # stray "Z" anyway, so the offset it writes is ignored.
            try:
                wall = datetime.fromisoformat(str(args[key]).strip().replace("Z", "+00:00"))
            except ValueError:
                continue
            local = wall.replace(tzinfo=None).replace(tzinfo=zone)
            if len(named) == 1 and local.weekday() != named[0]:
                local = local + timedelta(days=(named[0] - local.weekday()) % 7)
            while local.astimezone(timezone.utc) < now and (args.get("recurrence") or len(named) == 1):
                local = local + timedelta(days=7 if (args.get("recurrence") == "weekly" or named) else 1)
            args[key] = local.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return steps


# ─── Agent execution ──────────────────────────────────────────────────────────

class AgentContext:
    def __init__(self, db: Session, user: User, run: AiAgentRun, notify):
        self.db = db
        self.user = user
        self.run = run
        self.notify = notify
        self.org_id = getattr(user, "organization_id", None)
        self.unscoped = is_site_admin(user)  # Dilarion admins reach every organization
        self.zone = user_zone(db, user.id)

    def people(self):
        q = self.db.query(User).filter(User.is_active == True)  # noqa: E712
        return q if self.unscoped else q.filter(User.organization_id == self.org_id)

    def board_org(self) -> int:
        return resolve_org(self.db, self.user)

    def member(self, name: Optional[str]) -> User:
        if not name or str(name).lower() in ("me", "myself", "self"):
            if self.run.for_user_id and self.run.for_user_id != self.user.id:
                return self.db.get(User, self.run.for_user_id)
            return self.user
        n = str(name).lstrip("@").strip()
        q = self.people()
        u = q.filter(User.username.ilike(n)).first() or q.filter(User.full_name.ilike(n)).first()
        if not u:
            cands = q.filter(User.full_name.ilike(f"%{n}%")).limit(2).all()
            u = cands[0] if len(cands) == 1 else None
        if not u:
            raise ValueError(f"No one named '{n}' in your organization")
        return u


async def _tool_create_reminder(ctx: AgentContext, a: dict) -> dict:
    target = ctx.member(a.get("for"))
    if target.id != ctx.user.id:
        if not (has_permission(ctx.db, ctx.user, "set_reminders_for_others")
                and has_permission(ctx.db, ctx.user, "ai_agents_for_others")):
            raise PermissionError("Your role cannot set reminders for other members")
        if not accepts_from_others(ctx.db, target.id) or tool_disabled(ctx.db, target.id, "create_reminder"):
            raise PermissionError(f"{target.username} doesn't accept reminders from other people's agents")
    at = _parse_dt(a.get("remind_at"), ctx.zone)
    if not at:
        raise ValueError("remind_at is missing or not a valid time")
    r = reminders_mod.create_reminder(ctx.db, target.id, a.get("title"), at, note=a.get("note"),
                                      recurrence=a.get("recurrence") or None, created_by_id=ctx.user.id,
                                      source="ai_agent")
    return {"reminder_id": r.id, "for": target.username, "remind_at": _iso(r.remind_at)}


async def _tool_create_task(ctx: AgentContext, a: dict) -> dict:
    names = a.get("assignees") or ["me"]
    people = [ctx.member(n) for n in names][:50]
    if any(p.id != ctx.user.id for p in people):
        if not (has_permission(ctx.db, ctx.user, "assign_tasks") and has_permission(ctx.db, ctx.user, "ai_agents_for_others")):
            raise PermissionError("Your role cannot assign tasks to other members")
        refusing = [p.username for p in people if p.id != ctx.user.id
                    and (not accepts_from_others(ctx.db, p.id) or tool_disabled(ctx.db, p.id, "create_task"))]
        if refusing:
            raise PermissionError(f"{', '.join(refusing)} don't accept tasks from other people's agents")
    title = str(a.get("title") or "").strip()[:255]
    if not title:
        raise ValueError("title is required")
    due = _parse_dt(a.get("due_at"), ctx.zone)
    t = Task(created_by_id=ctx.user.id, title=title, description=a.get("description"),
             due_at=due.replace(tzinfo=None) if due else None, status="open")
    ctx.db.add(t)
    ctx.db.flush()
    for p in {p.id: p for p in people}.values():
        ctx.db.add(TaskAssignee(task_id=t.id, user_id=p.id))
    await ctx.notify([p.id for p in people if p.id != ctx.user.id],
                     {"type": "task_assigned", "data": {"task_id": t.id, "title": title, "by": ctx.user.id}})
    return {"task_id": t.id, "assignees": [p.username for p in people]}


async def _tool_add_whiteboard_note(ctx: AgentContext, a: dict) -> dict:
    board_name = str(a.get("board") or "org").strip()
    db = ctx.db
    if board_name.lower() in ("org", "organization", "organisation"):
        if not has_permission(db, ctx.user, "edit_org_whiteboard"):
            raise PermissionError("Your role cannot edit the organization whiteboard")
        org_id = ctx.board_org()
        board = db.query(wb_mod.Whiteboard).filter(wb_mod.Whiteboard.organization_id == org_id,
                                                   wb_mod.Whiteboard.scope == "org").first()
        if not board:
            board = wb_mod.Whiteboard(organization_id=org_id, scope="org", title="Organization whiteboard",
                                      created_by_id=ctx.user.id, elements={})
            db.add(board)
            db.flush()
    else:
        from database_models import Group
        my_groups = [m.group_id for m in db.query(GroupMember.group_id).filter(GroupMember.user_id == ctx.user.id).all()]
        g = db.query(Group).filter(Group.id.in_(my_groups or [-1]), Group.name.ilike(board_name)).first()
        if not g:
            raise ValueError(f"You are not in a group called '{board_name}'")
        if not has_permission(db, ctx.user, "create_group_whiteboards", g.id):
            raise PermissionError("Your role cannot edit whiteboards in that group")
        board = db.query(wb_mod.Whiteboard).filter(wb_mod.Whiteboard.group_id == g.id,
                                                   wb_mod.Whiteboard.is_archived == False).order_by(  # noqa: E712
            wb_mod.Whiteboard.updated_at.desc()).first()
        if not board:
            board = wb_mod.Whiteboard(organization_id=g.organization_id or ctx.board_org(), group_id=g.id, scope="group",
                                      title=f"{g.name} whiteboard", created_by_id=ctx.user.id, elements={})
            db.add(board)
            db.flush()
    n = len(board.elements or {})
    kind = "task" if a.get("kind") == "task" else "sticky"
    el = wb_mod.add_element(db, board, {
        "type": kind, "text": str(a.get("text") or "")[:2000], "color": a.get("color") or "#FDE68A",
        "x": 80 + (n % 6) * 240, "y": 80 + (n // 6) * 200, "w": 220, "h": 180, "source": "ai_agent",
    }, ctx.user.id)
    return {"board_id": board.id, "element_id": el["id"]}


async def _tool_draft_meeting(ctx: AgentContext, a: dict) -> dict:
    at = _parse_dt(a.get("scheduled_at"), ctx.zone)
    people = [ctx.member(n).username for n in (a.get("participants") or [])][:50]
    return {"draft": {"title": a.get("title"), "scheduled_at": _iso(at),
                      "duration_minutes": int(a.get("duration_minutes") or 30), "participants": people},
            "needs_confirmation": True}


async def _tool_find_people(ctx: AgentContext, a: dict) -> dict:
    q = str(a.get("query") or "").strip()
    rows = ctx.people().filter(or_(User.full_name.ilike(f"%{q}%"), User.username.ilike(f"%{q}%"),
                                         User.department.ilike(f"%{q}%"))).limit(10).all()
    return {"people": [{"username": u.username, "full_name": u.full_name, "department": u.department} for u in rows]}


TOOL_FUNCS = {
    "create_reminder": _tool_create_reminder,
    "create_task": _tool_create_task,
    "add_whiteboard_note": _tool_add_whiteboard_note,
    "draft_meeting": _tool_draft_meeting,
    "find_people": _tool_find_people,
}


async def plan_run(db: Session, user: User, run: AiAgentRun) -> None:
    roster_q = db.query(User.username, User.full_name).filter(User.is_active == True)  # noqa: E712
    if not is_site_admin(user):
        roster_q = roster_q.filter(User.organization_id == user.organization_id)
    members = roster_q.limit(200).all()
    roster = "\n".join(f"- {m.username} ({m.full_name or ''})" for m in members)
    zone = user_zone(db, user.id)
    blocked = prefs_dict(db.get(AiPreference, int(user.id)))["disabled_tools"]
    prompt = (f"{time_context(zone)}\n"
              + (f"Do NOT use these tools (the user turned them off): {', '.join(blocked)}\n" if blocked else "")
              + f"Requested by: {user.username}\nMembers of the organization:\n{roster}\n\n"
              f"Instruction: {run.instruction}")
    parsed = _loads(await _ollama_generate(_PLAN_PROMPT, prompt, json_mode=True, timeout=120.0))
    if parsed is None:
        raise RuntimeError("The AI model is unavailable right now")
    steps = []
    for s in (parsed.get("steps") or [])[:MAX_STEPS]:
        if isinstance(s, dict) and s.get("tool") in TOOLS and isinstance(s.get("args"), dict):
            if s["tool"] in blocked:
                continue
            steps.append({"tool": s["tool"], "args": s["args"], "why": str(s.get("why") or "")[:300]})
    run.plan = normalize_plan_times(steps, run.instruction, zone)
    run.title = str(parsed.get("title") or run.instruction)[:150]
    run.summary = str(parsed.get("summary") or "")[:1000]


async def execute_run(db: Session, user: User, run: AiAgentRun, notify) -> None:
    ctx = AgentContext(db, user, run, notify)
    run.status = "running"
    run.started_at = datetime.now(timezone.utc)
    db.commit()
    results = []
    for step in run.plan or []:
        db.refresh(run)
        if run.status == "cancelled":
            return
        entry = {"tool": step["tool"], "args": step["args"]}
        try:
            if tool_disabled(db, user.id, step["tool"]):
                raise PermissionError(f"{TOOL_LABELS.get(step['tool'], step['tool'])} is turned off in your AI settings")
            entry["result"] = await TOOL_FUNCS[step["tool"]](ctx, step["args"])
            entry["status"] = "done"
            db.commit()
        except (ValueError, PermissionError) as e:
            db.rollback()
            entry["status"] = "failed"
            entry["error"] = str(e)
        except Exception as e:
            db.rollback()
            logger.warning("agent step failed: %s", type(e).__name__)
            entry["status"] = "failed"
            entry["error"] = "Unexpected error"
        results.append(entry)
        run.steps = list(results)
        db.commit()
        await notify([user.id], {"type": "ai_agent_progress", "data": run_dict(run)})
    run.finished_at = datetime.now(timezone.utc)
    failed = [s for s in results if s["status"] == "failed"]
    run.status = "failed" if results and len(failed) == len(results) else "completed"
    if not results:
        run.status = "completed"
    db.commit()


# ─── Request bodies ───────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    instruction: str = Field(..., min_length=3, max_length=4000)
    for_user_id: Optional[int] = None
    require_approval: bool = True
    conversation_id: Optional[int] = None


class ConversationCreate(BaseModel):
    title: Optional[str] = Field(None, max_length=150)


class ChatSend(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000)


class PreferenceUpdate(BaseModel):
    auto_approve: Optional[bool] = None
    allow_from_others: Optional[bool] = None
    disabled_tools: Optional[List[str]] = None
    timezone: Optional[str] = Field(None, max_length=64)


class PlanEdit(BaseModel):
    plan: List[Dict[str, Any]]


# ─── Routes ───────────────────────────────────────────────────────────────────

def install_ai_routes(app: FastAPI, get_current_user, get_database_session, notify):

    def _require_ai(db: Session, user, agents: bool = False):
        if not has_permission(db, user, "use_ai"):
            raise HTTPException(status_code=403, detail="Your role cannot use Dilarion AI")
        if agents and not has_permission(db, user, "run_ai_agents"):
            raise HTTPException(status_code=403, detail="Your role cannot send AI agents")

    def _own_run(db: Session, user, run_id: int) -> AiAgentRun:
        r = db.query(AiAgentRun).filter(AiAgentRun.id == run_id, AiAgentRun.user_id == int(user.id)).first()
        if not r:
            raise HTTPException(status_code=404, detail="Agent run not found")
        return r

    def _own_conv(db: Session, user, conv_id: int) -> AiConversation:
        c = db.query(AiConversation).filter(AiConversation.id == conv_id, AiConversation.user_id == int(user.id)).first()
        if not c:
            raise HTTPException(status_code=404, detail="Conversation not found")
        return c

    async def _background(run_id: int, user_id: int, execute: bool):
        db = next(get_database_session())
        try:
            run = db.get(AiAgentRun, run_id)
            user = db.get(User, user_id)
            if not run or not user:
                return
            try:
                if run.plan is None:
                    await plan_run(db, user, run)
                    db.commit()
                if not execute:
                    run.status = "awaiting_approval"
                    db.commit()
                    await notify([user_id], {"type": "ai_agent_progress", "data": run_dict(run)})
                    return
                await execute_run(db, user, run, notify)
            except Exception as e:
                db.rollback()
                run.status = "failed"
                run.error = str(e)[:500] if isinstance(e, RuntimeError) else "The agent stopped unexpectedly"
                run.finished_at = datetime.now(timezone.utc)
                db.commit()
            await notify([user_id], {"type": "ai_agent_finished" if run.status != "awaiting_approval"
                                     else "ai_agent_progress", "data": run_dict(run)})
            if run.for_user_id and run.for_user_id != user_id and run.status == "completed":
                await notify([run.for_user_id], {"type": "ai_agent_done_for_you", "data": {
                    "run_id": run.id, "title": run.title, "by": user_id}})
        finally:
            db.close()

    def _start(db: Session, user, body: AgentCreate) -> AiAgentRun:
        _require_ai(db, user, agents=True)
        if body.for_user_id and body.for_user_id != int(user.id):
            if not has_permission(db, user, "ai_agents_for_others"):
                raise HTTPException(status_code=403, detail="Your role cannot send agents on someone else's behalf")
            tq = db.query(User).filter(User.id == body.for_user_id)
            if not is_site_admin(user):
                tq = tq.filter(User.organization_id == user.organization_id)
            target = tq.first()
            if not target:
                raise HTTPException(status_code=404, detail="Member not found in your organization")
        # Full control: the user's auto-approve setting overrides a request to ask first.
        needs_approval = body.require_approval and not auto_approve_enabled(db, int(user.id))
        run = AiAgentRun(user_id=int(user.id), organization_id=user.organization_id,
                         for_user_id=body.for_user_id or int(user.id), conversation_id=body.conversation_id,
                         instruction=body.instruction.strip(), require_approval=1 if needs_approval else 0,
                         status="planning")
        db.add(run)
        db.commit()
        asyncio.create_task(_background(run.id, int(user.id), execute=not needs_approval))
        return run

    # Preferences

    @app.get("/ai/preferences")
    async def get_preferences(request: Request, current_user=Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
        remember_timezone(db, int(current_user.id), request)
        out = prefs_dict(db.get(AiPreference, int(current_user.id)))
        out["tools"] = [{"id": k, "label": v} for k, v in TOOL_LABELS.items()]
        return out

    @app.put("/ai/preferences")
    async def put_preferences(body: PreferenceUpdate, current_user=Depends(get_current_user),
                              db: Session = Depends(get_database_session)):
        """Partial update: only the fields sent change."""
        row = _prefs(db, int(current_user.id))
        if body.auto_approve is not None:
            row.auto_approve = body.auto_approve
        if body.allow_from_others is not None:
            row.allow_from_others = body.allow_from_others
        if body.disabled_tools is not None:
            row.disabled_tools = sorted({t for t in body.disabled_tools if t in TOOL_LABELS})
        if body.timezone:
            try:
                ZoneInfo(body.timezone)
            except (ZoneInfoNotFoundError, ValueError):
                raise HTTPException(status_code=400, detail="Unknown time zone")
            row.timezone = body.timezone
        db.commit()
        out = prefs_dict(row)
        out["tools"] = [{"id": k, "label": v} for k, v in TOOL_LABELS.items()]
        return out

    # Agents

    @app.post("/ai/agents", status_code=202)
    async def start_agent(body: AgentCreate, request: Request, current_user=Depends(get_current_user),
                          db: Session = Depends(get_database_session)):
        remember_timezone(db, int(current_user.id), request)
        return run_dict(_start(db, current_user, body))

    @app.get("/ai/agents")
    async def list_agents(status: Optional[str] = None, limit: int = Query(50, ge=1, le=200),
                          current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        q = db.query(AiAgentRun).filter(AiAgentRun.user_id == int(current_user.id))
        if status:
            q = q.filter(AiAgentRun.status == status)
        return {"runs": [run_dict(r) for r in q.order_by(AiAgentRun.id.desc()).limit(limit).all()]}

    @app.get("/ai/agents/{run_id}")
    async def get_agent(run_id: int, current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        return run_dict(_own_run(db, current_user, run_id))

    @app.put("/ai/agents/{run_id}/plan")
    async def edit_plan(run_id: int, body: PlanEdit, current_user=Depends(get_current_user),
                        db: Session = Depends(get_database_session)):
        """Let the user remove or tweak steps before approving."""
        r = _own_run(db, current_user, run_id)
        if r.status != "awaiting_approval":
            raise HTTPException(status_code=409, detail="Only a plan awaiting approval can be edited")
        clean = []
        for s in body.plan[:MAX_STEPS]:
            if s.get("tool") not in TOOLS or not isinstance(s.get("args"), dict):
                raise HTTPException(status_code=400, detail="Each step needs a known tool and args")
            clean.append({"tool": s["tool"], "args": s["args"], "why": str(s.get("why") or "")[:300]})
        r.plan = clean
        db.commit()
        return run_dict(r)

    @app.post("/ai/agents/{run_id}/approve", status_code=202)
    async def approve_agent(run_id: int, current_user=Depends(get_current_user),
                            db: Session = Depends(get_database_session)):
        r = _own_run(db, current_user, run_id)
        if r.status != "awaiting_approval":
            raise HTTPException(status_code=409, detail=f"Run is {r.status}, not awaiting approval")
        _require_ai(db, current_user, agents=True)
        r.status = "running"
        db.commit()
        asyncio.create_task(_background(r.id, int(current_user.id), execute=True))
        return run_dict(r)

    @app.post("/ai/agents/{run_id}/cancel")
    async def cancel_agent(run_id: int, current_user=Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
        r = _own_run(db, current_user, run_id)
        if r.status in ("completed", "failed", "cancelled"):
            raise HTTPException(status_code=409, detail=f"Run already {r.status}")
        r.status = "cancelled"
        r.finished_at = datetime.now(timezone.utc)
        db.commit()
        return run_dict(r)

    # Conversations (the AI page)

    @app.get("/ai/conversations")
    async def list_conversations(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        rows = db.query(AiConversation).filter(AiConversation.user_id == int(current_user.id)).order_by(
            AiConversation.updated_at.desc()).limit(200).all()
        return {"conversations": [{"id": c.id, "title": c.title, "updated_at": _iso(c.updated_at)} for c in rows]}

    @app.post("/ai/conversations", status_code=201)
    async def create_conversation(body: ConversationCreate, current_user=Depends(get_current_user),
                                  db: Session = Depends(get_database_session)):
        _require_ai(db, current_user)
        c = AiConversation(user_id=int(current_user.id), title=(body.title or "New chat").strip() or "New chat")
        db.add(c)
        db.commit()
        return {"id": c.id, "title": c.title, "messages": []}

    @app.delete("/ai/conversations", status_code=204)
    async def clear_conversations(current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        """Delete every AI chat of the caller (Settings > AI > Clear chat history)."""
        ids = [c.id for c in db.query(AiConversation.id).filter(AiConversation.user_id == int(current_user.id)).all()]
        if ids:
            db.query(AiMessage).filter(AiMessage.conversation_id.in_(ids)).delete(synchronize_session=False)
            db.query(AiConversation).filter(AiConversation.id.in_(ids)).delete(synchronize_session=False)
        db.commit()

    @app.get("/ai/conversations/{conv_id}")
    async def get_conversation(conv_id: int, current_user=Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
        c = _own_conv(db, current_user, conv_id)
        msgs = db.query(AiMessage).filter(AiMessage.conversation_id == c.id).order_by(AiMessage.id).all()
        return {"id": c.id, "title": c.title, "messages": [msg_dict(m) for m in msgs]}

    @app.delete("/ai/conversations/{conv_id}", status_code=204)
    async def delete_conversation(conv_id: int, current_user=Depends(get_current_user),
                                  db: Session = Depends(get_database_session)):
        c = _own_conv(db, current_user, conv_id)
        db.query(AiMessage).filter(AiMessage.conversation_id == c.id).delete()
        db.delete(c)
        db.commit()

    @app.post("/ai/conversations/{conv_id}/messages")
    async def send_message(conv_id: int, body: ChatSend, request: Request, current_user=Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
        _require_ai(db, current_user)
        remember_timezone(db, int(current_user.id), request)
        c = _own_conv(db, current_user, conv_id)
        history = db.query(AiMessage).filter(AiMessage.conversation_id == c.id).order_by(AiMessage.id.desc()).limit(20).all()
        transcript = "\n".join(f"{m.role}: {m.content}" for m in reversed(history))
        user_msg = AiMessage(conversation_id=c.id, role="user", content=body.text.strip())
        db.add(user_msg)
        db.commit()
        prompt = (f"{time_context(user_zone(db, current_user.id))}\n"
                  f"Conversation so far:\n{transcript or '(none)'}\n\nuser: {body.text.strip()}")
        parsed = _loads(await _ollama_generate(_CHAT_PROMPT, prompt, json_mode=True))
        if parsed is None:
            raise HTTPException(status_code=502, detail="Dilarion AI is unavailable right now — please try again")
        reply = str(parsed.get("reply") or "").strip()[:4000] or "I'm here to help."
        run = None
        instruction = parsed.get("agent_instruction")
        if instruction and has_permission(db, current_user, "run_ai_agents"):
            run = _start(db, current_user, AgentCreate(instruction=str(instruction)[:4000], require_approval=True,
                                                       conversation_id=c.id))
        bot = AiMessage(conversation_id=c.id, role="assistant", content=reply, agent_run_id=run.id if run else None)
        db.add(bot)
        if c.title == "New chat" and parsed.get("title"):
            c.title = str(parsed["title"])[:150]
        c.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {"user_message": msg_dict(user_msg), "assistant_message": msg_dict(bot),
                "agent_run": run_dict(run) if run else None, "title": c.title}
