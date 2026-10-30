"""Live decoys and event monitoring.

Serves a decoy admin portal and canary URLs. Every visit, sign-in attempt or canary request is
recorded as a DeceptionEvent (source IP, user agent, detail) and, when it involves a registered
honeytoken, attributed to that token's case. Captured events can be snapshotted into hashed
evidence from the dashboard. Keep decoys on infrastructure you control.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from ..db import DeceptionEvent, Honeytoken, SessionLocal, audit

router = APIRouter()


def _record_hit(request: Request, decoy: str, detail: dict, token_value: str | None = None):
    with SessionLocal() as db:
        ht = None
        if token_value:
            for h in db.execute(select(Honeytoken)).scalars():
                if token_value in (h.value, h.secret) or (h.token_type == "canary_url" and h.secret == token_value):
                    ht = h
                    break
        if ht:
            detail["token_value"] = ht.value
            detail["honeytoken_label"] = ht.label
        ev = DeceptionEvent(case_id=ht.case_id if ht else None, decoy=decoy,
                            src_ip=request.client.host if request.client else "",
                            user_agent=request.headers.get("user-agent", "")[:500],
                            detail_json=json.dumps(detail), honeytoken_id=ht.id if ht else None)
        db.add(ev)
        audit(db, "decoy", f"deception.{decoy}", f"src={ev.src_ip} honeytoken={ht.id if ht else '-'}", ev.case_id)
        db.commit()


DECOY_LOGIN = """<!doctype html><html><head><title>Admin Console</title><meta name=viewport content="width=device-width">
<style>body{font-family:system-ui;background:#f3f4f6;display:grid;place-items:center;height:100vh;margin:0}
form{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 10px #0002;width:300px}
input{width:100%;padding:9px;margin:6px 0 14px;box-sizing:border-box}button{width:100%;padding:10px}</style></head>
<body><form method=post><h3>Admin Console</h3><label>Username<input name=username></label>
<label>Password<input name=password type=password></label><button>Sign in</button><p style="color:#b00">{msg}</p></form></body></html>"""


@router.get("/decoy/admin", response_class=HTMLResponse, include_in_schema=False)
def decoy_admin_get(request: Request):
    _record_hit(request, "admin_portal_view", {"path": "/decoy/admin"})
    return DECOY_LOGIN.replace("{msg}", "")


@router.post("/decoy/admin", response_class=HTMLResponse, include_in_schema=False)
async def decoy_admin_post(request: Request):
    form = await request.form()
    u, p = str(form.get("username", "")), str(form.get("password", ""))
    _record_hit(request, "admin_portal_login", {"username": u, "password_len": len(p)}, token_value=u or None)
    return DECOY_LOGIN.replace("{msg}", "Invalid credentials")


@router.get("/decoy/t/{tok}", include_in_schema=False)
def canary(tok: str, request: Request):
    _record_hit(request, "canary_url", {"token": tok}, token_value=tok)
    return HTMLResponse("<html><body><h3>404 Not Found</h3></body></html>", status_code=404)
