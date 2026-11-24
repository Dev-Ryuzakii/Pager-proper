"""Whiteboards as their own page, not only inside a meeting.

Two scopes:
  org    one board per organization, every member sees it (the org dashboard).
  group  boards for a group; members of that group see them.

A board is a set of elements (sticky, text, shape, pen stroke, arrow, connector,
frame, image, task card). Clients send element ops; the server applies them,
bumps the board version and fans the ops out to everyone viewing it over the
websocket ("whiteboard_ops"). Last write per element wins.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from database_models import Base, Group, GroupMember, User
from org_roles import has_permission, is_site_admin, org_scope, organization_choices, resolve_org

ELEMENT_TYPES = {"sticky", "text", "rect", "ellipse", "diamond", "pen", "arrow", "line",
                 "connector", "frame", "image", "task", "mindmap", "comment"}
MAX_ELEMENTS = 5000
MAX_OPS = 500


class Whiteboard(Base):
    __tablename__ = "whiteboards"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)
    scope = Column(String(10), nullable=False, default="group")  # org / group
    title = Column(String(150), nullable=False, default="Whiteboard")
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    elements = Column(JSON, nullable=False, default=dict)  # element id -> element
    viewport = Column(JSON, nullable=True)  # default {x, y, zoom}
    version = Column(Integer, nullable=False, default=0)
    locked = Column(Boolean, default=False, nullable=False)  # only admins edit
    is_archived = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class WhiteboardFavorite(Base):
    __tablename__ = "whiteboard_favorites"

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    whiteboard_id = Column(Integer, ForeignKey("whiteboards.id", ondelete="CASCADE"), primary_key=True)


class BoardCreate(BaseModel):
    title: str = Field("Whiteboard", min_length=1, max_length=150)


class BoardUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=150)
    locked: Optional[bool] = None
    archived: Optional[bool] = None
    viewport: Optional[Dict[str, float]] = None


class ElementOp(BaseModel):
    op: str = Field(..., description="upsert or delete")
    id: Optional[str] = Field(None, max_length=64)
    element: Optional[Dict[str, Any]] = None


class OpsBody(BaseModel):
    base_version: Optional[int] = None
    ops: List[ElementOp] = Field(..., max_length=MAX_OPS)


def _iso(dt):
    if dt is None:
        return None
    dt = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def board_summary(b: Whiteboard, favorite: bool = False) -> dict:
    return {
        "id": b.id, "scope": b.scope, "group_id": b.group_id, "title": b.title,
        "version": b.version, "locked": b.locked, "archived": b.is_archived,
        "element_count": len(b.elements or {}), "favorite": favorite,
        "updated_at": _iso(b.updated_at), "created_by_id": b.created_by_id,
    }


def board_full(b: Whiteboard, favorite: bool = False, can_edit: bool = False) -> dict:
    d = board_summary(b, favorite)
    d.update({"elements": list((b.elements or {}).values()), "viewport": b.viewport, "can_edit": can_edit})
    return d


def _clean_element(eid: str, el: Dict[str, Any], user_id: int) -> Dict[str, Any]:
    t = el.get("type")
    if t not in ELEMENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown element type: {t}")
    out = dict(el)
    out["id"] = eid
    out["updated_by"] = user_id
    out["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if len(str(out)) > 200_000:
        raise HTTPException(status_code=413, detail="Element too large")
    return out


def add_element(db: Session, board: Whiteboard, element: Dict[str, Any], user_id: int) -> dict:
    """Used by the AI agent runner to drop a sticky or task card on a board."""
    eid = uuid.uuid4().hex[:16]
    els = dict(board.elements or {})
    els[eid] = _clean_element(eid, element, user_id)
    board.elements = els
    board.version = (board.version or 0) + 1
    board.updated_by_id = user_id
    return els[eid]


def install_whiteboard_routes(app: FastAPI, get_current_user, get_database_session, notify):


    def _member_of(db: Session, group_id: int, user_id: int) -> Optional[GroupMember]:
        return db.query(GroupMember).filter(GroupMember.group_id == group_id, GroupMember.user_id == user_id).first()

    def _org_board(db: Session, org_id: int, user_id: int) -> Whiteboard:
        b = db.query(Whiteboard).filter(Whiteboard.organization_id == org_id, Whiteboard.scope == "org").first()
        if not b:
            b = Whiteboard(organization_id=org_id, scope="org", title="Organization whiteboard",
                           created_by_id=user_id, elements={})
            db.add(b)
            db.flush()
        return b

    def _can_view(db: Session, user, b: Whiteboard) -> bool:
        if is_site_admin(user):
            return True
        if int(b.organization_id) != int(getattr(user, "organization_id", 0) or 0):
            return False
        if b.scope == "org":
            return has_permission(db, user, "view_org_whiteboard")
        return _member_of(db, b.group_id, int(user.id)) is not None or has_permission(db, user, "manage_groups")

    def _can_edit(db: Session, user, b: Whiteboard) -> bool:
        if b.is_archived or not _can_view(db, user, b):
            return False
        if b.scope == "org":
            if b.locked:
                return has_permission(db, user, "manage_groups")
            return has_permission(db, user, "edit_org_whiteboard")
        gm = _member_of(db, b.group_id, int(user.id))
        if b.locked:
            return (gm is not None and gm.role in ("owner", "admin")) or has_permission(db, user, "manage_groups")
        return has_permission(db, user, "create_group_whiteboards", b.group_id)

    def _can_manage(db: Session, user, b: Whiteboard) -> bool:
        if has_permission(db, user, "manage_groups"):
            return True
        if b.scope == "group":
            gm = _member_of(db, b.group_id, int(user.id))
            return (gm is not None and gm.role in ("owner", "admin")) or b.created_by_id == int(user.id)
        return False

    def _load(db: Session, user, board_id: int) -> Whiteboard:
        b = db.query(Whiteboard).filter(Whiteboard.id == board_id).first()
        if not b or not _can_view(db, user, b):
            raise HTTPException(status_code=404, detail="Whiteboard not found")
        return b

    def _audience(db: Session, b: Whiteboard) -> List[int]:
        if b.scope == "org":
            return [u.id for u in db.query(User.id).filter(User.organization_id == b.organization_id,
                                                           User.is_active == True).all()]  # noqa: E712
        return [m.user_id for m in db.query(GroupMember.user_id).filter(GroupMember.group_id == b.group_id).all()]

    def _fav(db: Session, user_id: int, board_id: int) -> bool:
        return db.query(WhiteboardFavorite).filter(WhiteboardFavorite.user_id == user_id,
                                                   WhiteboardFavorite.whiteboard_id == board_id).first() is not None

    @app.get("/whiteboards")
    async def list_whiteboards(include_archived: bool = False, scope: Optional[int] = Depends(org_scope), current_user=Depends(get_current_user),
                               db: Session = Depends(get_database_session)):
        """The whiteboard page sidebar: the org board first, then boards of groups you are in."""
        org_id = resolve_org(db, current_user, scope)
        org_board = _org_board(db, org_id, int(current_user.id))
        db.commit()
        if is_site_admin(current_user):  # every group board in the organization
            group_ids = [g.id for g in db.query(Group.id).filter(Group.organization_id == org_id).all()]
        else:
            group_ids = [m.group_id for m in db.query(GroupMember.group_id).filter(
                GroupMember.user_id == int(current_user.id)).all()]
        q = db.query(Whiteboard).filter(Whiteboard.organization_id == org_id, Whiteboard.scope == "group",
                                        Whiteboard.group_id.in_(group_ids or [-1]))
        if not include_archived:
            q = q.filter(Whiteboard.is_archived == False)  # noqa: E712
        favs = {f.whiteboard_id for f in db.query(WhiteboardFavorite).filter(
            WhiteboardFavorite.user_id == int(current_user.id)).all()}
        names = {g.id: g.name for g in db.query(Group.id, Group.name).filter(Group.id.in_(group_ids or [-1])).all()}
        groups = []
        for b in q.order_by(Whiteboard.updated_at.desc()).all():
            d = board_summary(b, b.id in favs)
            d["group_name"] = names.get(b.group_id)
            groups.append(d)
        org = board_summary(org_board, org_board.id in favs) if has_permission(db, current_user, "view_org_whiteboard") else None
        return {"org": org, "groups": groups, "organization_id": org_id,
                "organizations": organization_choices(db, current_user)}

    @app.get("/whiteboards/org")
    async def get_org_whiteboard(scope: Optional[int] = Depends(org_scope), current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        org_id = resolve_org(db, current_user, scope)
        b = _org_board(db, org_id, int(current_user.id))
        db.commit()
        if not _can_view(db, current_user, b):
            raise HTTPException(status_code=403, detail="Your role cannot view the organization whiteboard")
        return board_full(b, _fav(db, int(current_user.id), b.id), _can_edit(db, current_user, b))

    @app.get("/groups/{group_id}/whiteboards")
    async def list_group_whiteboards(group_id: int, scope: Optional[int] = Depends(org_scope), current_user=Depends(get_current_user),
                                     db: Session = Depends(get_database_session)):
        org_id = resolve_org(db, current_user, scope)
        if not _member_of(db, group_id, int(current_user.id)) and not has_permission(db, current_user, "manage_groups"):
            raise HTTPException(status_code=404, detail="Group not found")
        rows = db.query(Whiteboard).filter(Whiteboard.organization_id == org_id, Whiteboard.group_id == group_id,
                                           Whiteboard.is_archived == False).order_by(Whiteboard.updated_at.desc()).all()  # noqa: E712
        return {"whiteboards": [board_summary(b) for b in rows]}

    @app.post("/groups/{group_id}/whiteboards", status_code=201)
    async def create_group_whiteboard(group_id: int, body: BoardCreate, scope: Optional[int] = Depends(org_scope), current_user=Depends(get_current_user),
                                      db: Session = Depends(get_database_session)):
        org_id = resolve_org(db, current_user, scope)
        g = db.query(Group).filter(Group.id == group_id).first()
        if not g or (g.organization_id and int(g.organization_id) != org_id):
            raise HTTPException(status_code=404, detail="Group not found")
        if not _member_of(db, group_id, int(current_user.id)) and not is_site_admin(current_user):
            raise HTTPException(status_code=403, detail="Join the group first")
        if not has_permission(db, current_user, "create_group_whiteboards", group_id):
            raise HTTPException(status_code=403, detail="Your role cannot create whiteboards in this group")
        b = Whiteboard(organization_id=org_id, group_id=group_id, scope="group", title=body.title.strip(),
                       created_by_id=int(current_user.id), elements={})
        db.add(b)
        db.commit()
        await notify(_audience(db, b), {"type": "whiteboard_created", "data": board_summary(b)})
        return board_full(b, False, True)

    @app.get("/whiteboards/{board_id}")
    async def get_whiteboard(board_id: int, since_version: Optional[int] = Query(None),
                             current_user=Depends(get_current_user), db: Session = Depends(get_database_session)):
        b = _load(db, current_user, board_id)
        if since_version is not None and since_version == b.version:
            return {"id": b.id, "version": b.version, "unchanged": True}
        return board_full(b, _fav(db, int(current_user.id), b.id), _can_edit(db, current_user, b))

    @app.patch("/whiteboards/{board_id}")
    async def update_whiteboard(board_id: int, body: BoardUpdate, current_user=Depends(get_current_user),
                                db: Session = Depends(get_database_session)):
        b = _load(db, current_user, board_id)
        if body.viewport is not None and _can_edit(db, current_user, b):
            b.viewport = body.viewport
        if body.title is not None or body.locked is not None or body.archived is not None:
            if not _can_manage(db, current_user, b):
                raise HTTPException(status_code=403, detail="Only board owners and admins can change this")
            if body.title is not None:
                b.title = body.title.strip()
            if body.locked is not None:
                b.locked = body.locked
            if body.archived is not None:
                if b.scope == "org":
                    raise HTTPException(status_code=400, detail="The organization whiteboard cannot be archived")
                b.is_archived = body.archived
        db.commit()
        await notify(_audience(db, b), {"type": "whiteboard_updated", "data": board_summary(b)})
        return board_summary(b)

    @app.delete("/whiteboards/{board_id}", status_code=204)
    async def delete_whiteboard(board_id: int, current_user=Depends(get_current_user),
                                db: Session = Depends(get_database_session)):
        b = _load(db, current_user, board_id)
        if b.scope == "org":
            raise HTTPException(status_code=400, detail="The organization whiteboard cannot be deleted")
        if not _can_manage(db, current_user, b):
            raise HTTPException(status_code=403, detail="Only board owners and admins can delete it")
        audience = _audience(db, b)
        db.query(WhiteboardFavorite).filter(WhiteboardFavorite.whiteboard_id == b.id).delete()
        db.delete(b)
        db.commit()
        await notify(audience, {"type": "whiteboard_deleted", "data": {"id": board_id}})

    @app.post("/whiteboards/{board_id}/ops")
    async def apply_ops(board_id: int, body: OpsBody, current_user=Depends(get_current_user),
                        db: Session = Depends(get_database_session)):
        b = _load(db, current_user, board_id)
        if not _can_edit(db, current_user, b):
            raise HTTPException(status_code=403, detail="You can view this whiteboard but not edit it")
        db.refresh(b, with_for_update=True)
        els = dict(b.elements or {})
        applied = []
        for op in body.ops:
            if op.op == "delete":
                if op.id and els.pop(op.id, None) is not None:
                    applied.append({"op": "delete", "id": op.id})
            elif op.op == "upsert":
                if not op.element:
                    raise HTTPException(status_code=400, detail="upsert needs an element")
                eid = op.id or op.element.get("id") or uuid.uuid4().hex[:16]
                if eid in els:
                    merged = {**els[eid], **op.element}
                else:
                    merged = op.element
                els[eid] = _clean_element(str(eid)[:64], merged, int(current_user.id))
                applied.append({"op": "upsert", "id": eid, "element": els[eid]})
            else:
                raise HTTPException(status_code=400, detail="op must be upsert or delete")
        if len(els) > MAX_ELEMENTS:
            raise HTTPException(status_code=413, detail=f"A whiteboard holds at most {MAX_ELEMENTS} elements")
        base = b.version or 0
        b.elements = els
        b.version = base + 1
        b.updated_by_id = int(current_user.id)
        db.commit()
        if applied:
            await notify(_audience(db, b), {"type": "whiteboard_ops", "data": {
                "board_id": b.id, "version": b.version, "ops": applied, "by": int(current_user.id)}})
        return {"version": b.version, "applied": applied,
                "stale": body.base_version is not None and body.base_version != base}

    @app.post("/whiteboards/{board_id}/cursor")
    async def share_cursor(board_id: int, x: float, y: float, current_user=Depends(get_current_user),
                           db: Session = Depends(get_database_session)):
        """Live presence: who is on the board and where their pointer is. Not stored."""
        b = _load(db, current_user, board_id)
        others = [u for u in _audience(db, b) if u != int(current_user.id)]
        await notify(others, {"type": "whiteboard_cursor", "data": {
            "board_id": b.id, "user_id": int(current_user.id), "name": current_user.full_name or current_user.username,
            "x": x, "y": y}})
        return {"ok": True}

    @app.put("/whiteboards/{board_id}/favorite")
    async def favorite_whiteboard(board_id: int, favorite: bool = True, current_user=Depends(get_current_user),
                                  db: Session = Depends(get_database_session)):
        b = _load(db, current_user, board_id)
        row = db.query(WhiteboardFavorite).filter(WhiteboardFavorite.user_id == int(current_user.id),
                                                  WhiteboardFavorite.whiteboard_id == b.id).first()
        if favorite and not row:
            db.add(WhiteboardFavorite(user_id=int(current_user.id), whiteboard_id=b.id))
        elif not favorite and row:
            db.delete(row)
        db.commit()
        return {"id": b.id, "favorite": favorite}
