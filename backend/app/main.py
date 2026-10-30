"""IDMF - Intelligent Deception & Media Forensics Platform: FastAPI application."""
from __future__ import annotations

import json
import shutil
from contextlib import asynccontextmanager
import tempfile
import time
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config
from .ai import assistant, insights as ai_insights, summarizer
from .auth import create_token, current_user, decode_token, hash_password, verify_password
from .core import correlation
from .core.integrity import file_hashes, store_write_once
from .core.pipeline import LAYER, MODULES, detect_module, run_module
from .db import (AuditLog, Case, DeceptionEvent, Evidence, Honeytoken, SessionLocal, User, audit, get_db,
                 init_db, utcnow, verify_audit_chain)
from .deception.decoys import router as decoy_router
from .deception.honeytokens import generate_honeytoken, honeytoken_document
from .demo import scenario as synth
from . import reporting

@asynccontextmanager
async def lifespan(_app):
    _startup()
    yield


app = FastAPI(title="IDMF - Intelligent Deception & Media Forensics Platform", version="1.1.0", lifespan=lifespan)
app.include_router(decoy_router)


# ----------------------------------------------------------------------------- startup
def _startup():
    init_db()
    with SessionLocal() as db:
        if not db.execute(select(User)).first():
            db.add(User(username="investigator", full_name="Demo Investigator",
                        pw_hash=hash_password("forensics123"), role="admin"))
            audit(db, "system", "user.seed", "Created demo account 'investigator'")
            db.commit()


# ----------------------------------------------------------------------------- schemas
class Credentials(BaseModel):
    username: str
    password: str
    full_name: str | None = ""


class CaseIn(BaseModel):
    name: str
    description: str | None = ""


class HoneytokenIn(BaseModel):
    token_type: str
    label: str | None = ""
    placed_at: str | None = ""


class ReportIn(BaseModel):
    use_llm: bool = False


# ----------------------------------------------------------------------------- helpers
def _case_or_404(db: Session, case_id: int) -> Case:
    c = db.get(Case, case_id)
    if not c:
        raise HTTPException(404, "Case not found")
    return c


def evidence_dict(e: Evidence, with_artifacts: bool = True) -> dict:
    a = e.analysis
    d = {"id": e.id, "case_id": e.case_id, "filename": e.filename, "module": e.module, "size": e.size,
         "sha256": e.sha256, "md5": e.md5, "integrity_ok": e.integrity_ok, "status": e.status, "error": e.error,
         "uploaded_by": e.uploaded_by, "uploaded_at": e.uploaded_at.isoformat(timespec="seconds"),
         "last_verified_at": e.last_verified_at.isoformat(timespec="seconds") if e.last_verified_at else None,
         "analysis_seconds": round(e.analysis_seconds, 3), "summary": a.get("summary", {}),
         "artifact_count": len(a.get("artifacts", []))}
    if with_artifacts:
        d["artifacts"] = a.get("artifacts", [])
    return d


def honeytoken_dicts(db: Session, case_id: int) -> list[dict]:
    return [{"id": h.id, "token_type": h.token_type, "label": h.label, "value": h.value, "secret": h.secret,
             "placed_at": h.placed_at, "group": h.placed_at or None,
             "created_at": h.created_at.isoformat(timespec="seconds")}
            for h in db.execute(select(Honeytoken).where(Honeytoken.case_id == case_id)).scalars()]


def ingest_file(db: Session, case: Case, src: Path, filename: str, actor: str, module_hint: str | None = None) -> Evidence:
    sha, md5 = file_hashes(src)
    stored = store_write_once(src, config.EVIDENCE_DIR, sha, filename)
    module = module_hint if module_hint in MODULES else detect_module(stored, filename)
    ev = Evidence(case_id=case.id, filename=filename, stored_path=str(stored), size=stored.stat().st_size,
                  sha256=sha, md5=md5, module=module, uploaded_by=actor, status="pending")
    db.add(ev)
    db.flush()
    audit(db, actor, "evidence.acquire", f"E{ev.id} {filename} sha256={sha}", case.id)
    analyse_evidence(db, ev, actor)
    return ev


def analyse_evidence(db: Session, ev: Evidence, actor: str) -> None:
    t = time.perf_counter()
    try:
        res = run_module(ev.module, Path(ev.stored_path), config.DERIVED_DIR / f"case{ev.case_id}", ev.filename)
        ev.module = res.get("module", ev.module)
        ev.analysis_json = json.dumps(res, default=str)
        ev.status, ev.error = "analyzed", ""
    except Exception as exc:  # keep evidence, record failure
        ev.status, ev.error = "error", f"{type(exc).__name__}: {exc}"
        ev.analysis_json = json.dumps({"module": ev.module, "summary": {}, "artifacts": []})
    ev.analysis_seconds = time.perf_counter() - t
    sha_after, _ = file_hashes(ev.stored_path)               # integrity check after analysis
    ev.integrity_ok = sha_after == ev.sha256
    ev.last_verified_at = utcnow()
    audit(db, actor, "evidence.analyse", f"E{ev.id} module={ev.module} status={ev.status} "
          f"post-analysis-hash={'match' if ev.integrity_ok else 'MISMATCH'}", ev.case_id)


def case_correlation(db: Session, case_id: int) -> tuple[list[dict], dict]:
    evs = db.execute(select(Evidence).where(Evidence.case_id == case_id, Evidence.status == "analyzed")).scalars().all()
    ed = [evidence_dict(e) for e in evs]
    corr = correlation.correlate(ed, honeytoken_dicts(db, case_id), {e.id: e.stored_path for e in evs})
    return ed, corr


# ----------------------------------------------------------------------------- auth
@app.post("/api/auth/register")
def register(c: Credentials, db: Session = Depends(get_db)):
    if len(c.username) < 3 or len(c.password) < 8:
        raise HTTPException(400, "Username needs 3+ characters and password 8+ characters")
    if db.execute(select(User).where(User.username == c.username)).first():
        raise HTTPException(409, "Username already exists")
    u = User(username=c.username, full_name=c.full_name or "", pw_hash=hash_password(c.password))
    db.add(u)
    audit(db, c.username, "user.register")
    db.commit()
    return {"token": create_token(u.username, u.role), "username": u.username, "role": u.role}


@app.post("/api/auth/login")
def login(c: Credentials, db: Session = Depends(get_db)):
    u = db.execute(select(User).where(User.username == c.username)).scalar_one_or_none()
    if not u or not verify_password(c.password, u.pw_hash):
        audit(db, c.username, "user.login_failed")
        db.commit()
        raise HTTPException(401, "Invalid username or password")
    audit(db, u.username, "user.login")
    db.commit()
    return {"token": create_token(u.username, u.role), "username": u.username, "role": u.role, "full_name": u.full_name}


@app.get("/api/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "full_name": user.full_name, "role": user.role}


# ----------------------------------------------------------------------------- cases
@app.get("/api/cases")
def list_cases(user: User = Depends(current_user), db: Session = Depends(get_db)):
    out = []
    for c in db.execute(select(Case).order_by(Case.created_at.desc())).scalars():
        evs = c.evidence
        out.append({"id": c.id, "name": c.name, "description": c.description, "status": c.status,
                    "created_by": c.created_by, "created_at": c.created_at.isoformat(timespec="seconds"),
                    "evidence_count": len(evs), "modules": sorted({e.module for e in evs}),
                    "integrity_ok": all(e.integrity_ok for e in evs)})
    return out


@app.post("/api/cases")
def create_case(c: CaseIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = Case(name=c.name, description=c.description or "", created_by=user.username)
    db.add(case)
    db.flush()
    audit(db, user.username, "case.create", case.name, case.id)
    db.commit()
    return {"id": case.id}


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    evs = [evidence_dict(e, with_artifacts=False) for e in c.evidence]
    sev = {}
    for e in c.evidence:
        for a in e.analysis.get("artifacts", []):
            sev[a.get("severity", "info")] = sev.get(a.get("severity", "info"), 0) + 1
    return {"id": c.id, "name": c.name, "description": c.description, "status": c.status, "created_by": c.created_by,
            "created_at": c.created_at.isoformat(timespec="seconds"), "evidence": evs, "severity_counts": sev,
            "honeytokens": len(honeytoken_dicts(db, case_id))}


@app.patch("/api/cases/{case_id}")
def update_case(case_id: int, body: dict, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    for k in ("name", "description", "status"):
        if k in body:
            setattr(c, k, body[k])
    audit(db, user.username, "case.update", json.dumps(body)[:200], case_id)
    db.commit()
    return {"ok": True}


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    audit(db, user.username, "case.delete", c.name, case_id)
    db.delete(c)
    db.commit()
    return {"ok": True}


# ----------------------------------------------------------------------------- evidence
@app.post("/api/cases/{case_id}/evidence")
async def upload_evidence(case_id: int, files: list[UploadFile] = File(...), module: str = Form(""),
                          user: User = Depends(current_user), db: Session = Depends(get_db)):
    case = _case_or_404(db, case_id)
    out = []
    for f in files:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            size = 0
            while chunk := await f.read(1024 * 1024):
                size += len(chunk)
                if size > config.MAX_UPLOAD_MB * 1024 * 1024:
                    raise HTTPException(413, f"{f.filename} exceeds {config.MAX_UPLOAD_MB} MB")
                tmp.write(chunk)
        ev = ingest_file(db, case, Path(tmp.name), f.filename or "upload.bin", user.username, module or None)
        Path(tmp.name).unlink(missing_ok=True)
        out.append(evidence_dict(ev, with_artifacts=False))
    db.commit()
    return out


@app.get("/api/cases/{case_id}/evidence")
def list_evidence(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return [evidence_dict(e, with_artifacts=False) for e in _case_or_404(db, case_id).evidence]


@app.get("/api/evidence/{ev_id}")
def get_evidence(ev_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = db.get(Evidence, ev_id)
    if not e:
        raise HTTPException(404, "Evidence not found")
    return evidence_dict(e)


@app.post("/api/evidence/{ev_id}/verify")
def verify_evidence(ev_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = db.get(Evidence, ev_id)
    if not e:
        raise HTTPException(404, "Evidence not found")
    sha, _ = file_hashes(e.stored_path)
    e.integrity_ok = sha == e.sha256
    e.last_verified_at = utcnow()
    audit(db, user.username, "evidence.verify", f"E{e.id} computed={sha} {'match' if e.integrity_ok else 'MISMATCH'}", e.case_id)
    db.commit()
    return {"id": e.id, "acquired_sha256": e.sha256, "current_sha256": sha, "integrity_ok": e.integrity_ok}


@app.post("/api/cases/{case_id}/verify")
def verify_case(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    res = [verify_evidence(e.id, user, db) for e in _case_or_404(db, case_id).evidence]
    return {"verified": len(res), "ok": sum(r["integrity_ok"] for r in res), "items": res}


@app.post("/api/evidence/{ev_id}/reanalyse")
def reanalyse(ev_id: int, module: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    e = db.get(Evidence, ev_id)
    if not e:
        raise HTTPException(404, "Evidence not found")
    if module in MODULES:
        e.module = module
    analyse_evidence(db, e, user.username)
    db.commit()
    return evidence_dict(e, with_artifacts=False)


@app.get("/api/evidence/{ev_id}/ela")
def ela_image(ev_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    decode_token(token)
    e = db.get(Evidence, ev_id)
    if not e:
        raise HTTPException(404)
    arts = e.analysis.get("artifacts", [])
    name = (arts[0]["detail"].get("ela_image") or arts[0]["detail"].get("waveform_image")) if arts else None
    p = config.DERIVED_DIR / f"case{e.case_id}" / (name or "")
    if not name or not p.exists():
        raise HTTPException(404, "No ELA map for this evidence")
    return FileResponse(p, media_type="image/png")


@app.get("/api/evidence/{ev_id}/raw")
def evidence_raw(ev_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    data = decode_token(token)
    e = db.get(Evidence, ev_id)
    if not e:
        raise HTTPException(404)
    with SessionLocal() as s2:
        audit(s2, data["sub"], "evidence.export", f"E{e.id} {e.filename}", e.case_id)
        s2.commit()
    return FileResponse(e.stored_path, filename=e.filename)


# ----------------------------------------------------------------------------- correlation / timeline
@app.get("/api/cases/{case_id}/correlation")
def get_correlation(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    t = time.perf_counter()
    ed, corr = case_correlation(db, case_id)
    corr["stats"]["seconds"] = round(time.perf_counter() - t, 4)
    corr["evidence"] = [{"id": e["id"], "filename": e["filename"], "module": e["module"]} for e in ed]
    return corr


@app.get("/api/cases/{case_id}/timeline")
def get_timeline(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    _, corr = case_correlation(db, case_id)
    return corr["timeline"]


# ----------------------------------------------------------------------------- deception
@app.get("/api/cases/{case_id}/honeytokens")
def list_honeytokens(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    return honeytoken_dicts(db, case_id)


@app.post("/api/cases/{case_id}/honeytokens")
def create_honeytoken(case_id: int, body: HoneytokenIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    _case_or_404(db, case_id)
    try:
        t = generate_honeytoken(body.token_type, body.label or "")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    h = Honeytoken(case_id=case_id, placed_at=body.placed_at or "", **t)
    db.add(h)
    db.flush()
    audit(db, user.username, "honeytoken.create", f"#{h.id} {h.token_type} {h.label}", case_id)
    db.commit()
    return honeytoken_dicts(db, case_id)[-1]


@app.post("/api/cases/{case_id}/honeytokens/register")
def register_honeytoken(case_id: int, body: dict, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Register an existing decoy value (e.g. one already planted in the environment)."""
    h = Honeytoken(case_id=case_id, token_type=body.get("token_type", "credential"), label=body.get("label", "Registered decoy"),
                   value=body["value"], secret=body.get("secret", ""), placed_at=body.get("placed_at", ""))
    db.add(h)
    db.flush()
    audit(db, user.username, "honeytoken.register", f"#{h.id} {h.token_type} {h.label}", case_id)
    db.commit()
    return {"id": h.id}


@app.get("/api/cases/{case_id}/honeytokens/decoy-document")
def decoy_document(case_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    decode_token(token)
    hts = honeytoken_dicts(db, case_id)
    if not hts:
        raise HTTPException(404, "Create honeytokens first")
    p = config.DERIVED_DIR / f"case{case_id}"
    p.mkdir(parents=True, exist_ok=True)
    f = p / "Passwords_backup.txt"
    f.write_text(honeytoken_document({}, hts))
    return FileResponse(f, filename="Passwords_backup.txt", media_type="text/plain")


@app.get("/api/cases/{case_id}/deception-events")
def list_decoy_events(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(DeceptionEvent).where((DeceptionEvent.case_id == case_id) | (DeceptionEvent.case_id.is_(None)))
                      .order_by(DeceptionEvent.ts.desc())).scalars()
    return [{"id": r.id, "decoy": r.decoy, "src_ip": r.src_ip, "user_agent": r.user_agent, "ts": r.ts.isoformat(timespec="seconds"),
             "honeytoken_id": r.honeytoken_id, "detail": json.loads(r.detail_json), "case_id": r.case_id} for r in rows]


@app.post("/api/cases/{case_id}/deception-events/import")
def import_decoy_events(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Snapshot captured decoy interactions into a hashed evidence item."""
    case = _case_or_404(db, case_id)
    rows = list_decoy_events(case_id, user, db)
    if not rows:
        raise HTTPException(400, "No decoy events captured yet")
    tmp = Path(tempfile.mkdtemp()) / f"decoy_events_{utcnow():%Y%m%dT%H%M%S}.json"
    tmp.write_text(json.dumps({"decoy_events": rows}, indent=1))
    ev = ingest_file(db, case, tmp, tmp.name, user.username, "deception")
    db.commit()
    return evidence_dict(ev, with_artifacts=False)


# ----------------------------------------------------------------------------- AI assistance
class AskIn(BaseModel):
    question: str
    use_llm: bool = True


def _verified(texts: list[str], ed: list[dict]) -> list[dict]:
    facts = {e["id"]: reporting.evidence_facts(e) for e in ed}
    return [{"text": t, **reporting.verify_sentence(t, facts)} for t in texts]


@app.get("/api/cases/{case_id}/ai/insights")
def ai_get_insights(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    ed, corr = case_correlation(db, case_id)
    ins = ai_insights.build_insights(ed, corr)
    summary = summarizer.summarize_case({"name": c.name}, ed, corr, ins)
    return {"summary": _verified(summary, ed),
            "evidence_summaries": [{"id": e["id"], "filename": e["filename"], "module": e["module"],
                                    **_verified([summarizer.summarize_evidence(e)], ed)[0]} for e in ed],
            **ins, "llm_configured": assistant.llm.configured()}


@app.post("/api/cases/{case_id}/ai/ask")
def ai_ask(case_id: int, body: AskIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    ed, corr = case_correlation(db, case_id)
    ins = ai_insights.build_insights(ed, corr)
    res = assistant.ask(body.question, ed, summarizer.summarize_case({"name": c.name}, ed, corr, ins), ins, body.use_llm)
    audit(db, user.username, "ai.ask", body.question[:200], case_id)
    db.commit()
    return res


@app.get("/api/cases/{case_id}/iocs.csv")
def ioc_export(case_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    data = decode_token(token)
    ed, corr = case_correlation(db, case_id)
    audit(db, data["sub"], "iocs.export", f"{len(ed)} evidence items", case_id)
    db.commit()
    return Response(ai_insights.ioc_csv(ed, corr), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=IDMF_case{case_id}_iocs.csv"})


@app.get("/api/cases/{case_id}/layers")
def platform_layers(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Counts per architecture layer, for the dashboard's platform map."""
    c = _case_or_404(db, case_id)
    by_mod, media_types = {}, {}
    for e in c.evidence:
        by_mod[e.module] = by_mod.get(e.module, 0) + 1
        if e.module == "media":
            t = e.analysis.get("summary", {}).get("type", "media")
            media_types[t] = media_types.get(t, 0) + 1
    events = db.query(DeceptionEvent).filter((DeceptionEvent.case_id == case_id) | (DeceptionEvent.case_id.is_(None))).count()
    return {"forensic_modules": {m: by_mod.get(m, 0) for m in ("email", "browser", "disk", "memory", "network")},
            "media": {t: media_types.get(t, 0) for t in ("image", "audio", "video")},
            "deception": {"honeypot_logs": by_mod.get("deception", 0), "honeytokens": len(honeytoken_dicts(db, case_id)),
                          "decoy_events": events},
            "report_ready": (config.DERIVED_DIR / f"case{case_id}" / "report.json").exists()}


# ----------------------------------------------------------------------------- reports
@app.post("/api/cases/{case_id}/report")
def make_report(case_id: int, body: ReportIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    c = _case_or_404(db, case_id)
    ed, corr = case_correlation(db, case_id)
    cd = {"id": c.id, "name": c.name, "description": c.description, "status": c.status, "created_by": c.created_by,
          "created_at": c.created_at.isoformat(timespec="seconds")}
    ins = ai_insights.build_insights(ed, corr)
    chain = [{"title": "Attack chain (MITRE ATT&CK mapping)",
              "sentences": [i["text"] for i in ins["items"] if i["kind"] == "attack_chain"]}]
    rep = reporting.build_report(cd, ed, corr, use_llm=body.use_llm, extra_sections=chain)
    rep["recommendations"] = ins["recommendations"]
    out = config.DERIVED_DIR / f"case{case_id}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    audit(db, user.username, "report.generate", f"{rep['generator']} traceability={rep['verification']['traceability']}", case_id)
    db.commit()
    return rep


@app.get("/api/cases/{case_id}/report.pdf")
def report_pdf(case_id: int, token: str = Query(...), db: Session = Depends(get_db)):
    data = decode_token(token)
    out = config.DERIVED_DIR / f"case{case_id}"
    rj = out / "report.json"
    if not rj.exists():
        raise HTTPException(404, "Generate the report first")
    rows = [{"ts": a.ts.isoformat(), "actor": a.actor, "action": a.action, "detail": a.detail, "entry_hash": a.entry_hash}
            for a in db.execute(select(AuditLog).where(AuditLog.case_id == case_id).order_by(AuditLog.id)).scalars()]
    pdf = reporting.report_pdf(json.loads(rj.read_text()), out / f"case{case_id}_report.pdf", rows)
    audit(db, data["sub"], "report.export_pdf", pdf.name, case_id)
    db.commit()
    return FileResponse(pdf, filename=f"IDMF_case{case_id}_report.pdf", media_type="application/pdf")


# ----------------------------------------------------------------------------- audit
@app.get("/api/cases/{case_id}/audit")
def case_audit(case_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    ok, bad = verify_audit_chain(db)
    rows = [{"id": a.id, "ts": a.ts.isoformat(timespec="seconds"), "actor": a.actor, "action": a.action, "detail": a.detail,
             "prev_hash": a.prev_hash, "entry_hash": a.entry_hash}
            for a in db.execute(select(AuditLog).where(AuditLog.case_id == case_id).order_by(AuditLog.id)).scalars()]
    return {"chain_ok": ok, "first_bad_entry": bad, "entries": rows}


# ----------------------------------------------------------------------------- demo
@app.post("/api/demo")
def load_demo(seed: int = 7, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Creates a case from a synthetic, labelled intrusion scenario (inert data)."""
    tmp = Path(tempfile.mkdtemp())
    man = synth.generate_scenario(tmp, seed)
    case = Case(name=f"Demo: {man['org']} phishing intrusion (seed {seed})",
                description="Synthetic multi-domain scenario: phishing e-mail, browser history, network capture, memory image, "
                            "honeypot log with stolen honeytoken credential, disk timeline, doctored image, plus unrelated "
                            "background evidence, an edited voicemail and a CCTV clip. All data is synthetic and inert.", created_by=user.username)
    db.add(case)
    db.flush()
    audit(db, user.username, "case.create", case.name, case.id)
    for h in man["honeytokens"]:
        db.add(Honeytoken(case_id=case.id, token_type=h["token_type"], label=h["label"], value=h["value"], secret=h["secret"],
                          placed_at="Decoy credentials file on file server \\\\fs01\\it\\Passwords_backup.txt"))
    for f in man["files"]:
        ingest_file(db, case, tmp / f["name"], f["name"], user.username)
    # extra media for the audio/video modules (unrelated to the intrusion)
    from .demo import media_samples
    media_samples.make_voicemail(tmp / "14_voicemail.wav", seed=seed, spliced=True)
    ingest_file(db, case, tmp / "14_voicemail.wav", "14_voicemail.wav", user.username)
    if media_samples.make_cctv_clip(tmp / "15_cctv_clip.mp4").get("created"):
        ingest_file(db, case, tmp / "15_cctv_clip.mp4", "15_cctv_clip.mp4", user.username)
    db.commit()
    shutil.rmtree(tmp, ignore_errors=True)
    return {"id": case.id, "name": case.name}


@app.get("/api/health")
def health():
    return {"ok": True, "time": utcnow().isoformat(), "llm": bool(config.LLM_PROVIDER and config.LLM_API_KEY)}


# ----------------------------------------------------------------------------- frontend
if config.FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=config.FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(config.FRONTEND_DIR / "index.html")
