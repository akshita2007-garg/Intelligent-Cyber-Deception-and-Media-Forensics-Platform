"""End-to-end tests:  python -m pytest -q"""
import os
import tempfile
from pathlib import Path

os.environ.setdefault("IDMF_DATA_DIR", tempfile.mkdtemp(prefix="idmf_test_"))

from fastapi.testclient import TestClient  # noqa: E402

from backend.app import reporting  # noqa: E402
from backend.app.core import correlation  # noqa: E402
from backend.app.core.integrity import file_hashes  # noqa: E402
from backend.app.core.pipeline import detect_module, run_module  # noqa: E402
from backend.app.demo import scenario as synth  # noqa: E402
from backend.app.main import app  # noqa: E402


def _case(tmp_path, seed=11):
    man = synth.generate_scenario(tmp_path, seed)
    evs = []
    for i, f in enumerate(man["files"], 1):
        p = tmp_path / f["name"]
        res = run_module(detect_module(p, f["name"]), p, tmp_path / "d", f["name"])
        evs.append({"id": i, "filename": f["name"], "module": res["module"], "sha256": file_hashes(p)[0],
                    "artifacts": res["artifacts"], "summary": res["summary"], "related": f["related"], "path": str(p)})
    return man, evs


def test_modules_route_and_extract(tmp_path):
    man, evs = _case(tmp_path)
    mods = {e["filename"]: e["module"] for e in evs}
    assert mods["01_phishing.eml"] == "email"
    assert mods["03_victim_capture.pcap"] == "network"
    assert mods["05_honeypot_cowrie.json"] == "deception"
    phish = next(e for e in evs if e["filename"] == "01_phishing.eml")
    values = {x["value"] for a in phish["artifacts"] for x in a["entities"]}
    assert man["attacker"]["payload_sha256"] in values
    assert man["attacker"]["ip"] in values


def test_correlation_groups_incident_without_background(tmp_path):
    man, evs = _case(tmp_path)
    corr = correlation.correlate(evs, man["honeytokens"], {e["id"]: e["path"] for e in evs}, threshold=3, window_min=15)
    assert corr["incidents"], "expected at least one incident"
    inc = set(corr["incidents"][0]["evidence_ids"])
    background = {e["id"] for e in evs if not e["related"]}
    assert not (inc & background)
    assert len(inc) >= 4


def test_report_is_fully_traceable_and_verifier_catches_fabrication(tmp_path):
    man, evs = _case(tmp_path)
    corr = correlation.correlate(evs, man["honeytokens"], None, threshold=3, window_min=15)
    rep = reporting.build_report({"id": 1, "name": "t"}, evs, corr)
    assert rep["verification"]["traceability"] == 1.0
    facts = {e["id"]: reporting.evidence_facts(e) for e in evs}
    bad = reporting.verify_sentence("The attacker used 203.0.113.250 [E1].", facts)
    assert bad["status"] == "contradicted"
    assert reporting.verify_sentence("No citation here.", facts)["status"] == "unsupported"


def test_integrity_detects_single_bit_flip(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"evidence" * 1000)
    h = file_hashes(p)[0]
    b = bytearray(p.read_bytes()); b[100] ^= 1; p.write_bytes(bytes(b))
    assert file_hashes(p)[0] != h


def test_api_demo_flow():
    with TestClient(app) as c:
        tok = c.post("/api/auth/login", json={"username": "investigator", "password": "forensics123"}).json()["token"]
        H = {"Authorization": f"Bearer {tok}"}
        cid = c.post("/api/demo?seed=21", headers=H).json()["id"]
        case = c.get(f"/api/cases/{cid}", headers=H).json()
        assert len(case["evidence"]) >= 14 and all(e["integrity_ok"] for e in case["evidence"])
        corr = c.get(f"/api/cases/{cid}/correlation", headers=H).json()
        assert corr["stats"]["incidents"] >= 1
        rep = c.post(f"/api/cases/{cid}/report", headers=H, json={"use_llm": False}).json()
        assert rep["verification"]["traceability"] == 1.0
        assert c.get(f"/api/cases/{cid}/report.pdf?token={tok}").content[:4] == b"%PDF"
        assert c.get(f"/api/cases/{cid}/audit", headers=H).json()["chain_ok"]
        assert c.get("/api/cases", headers={}).status_code == 401


def test_audio_splice_and_video_temporal(tmp_path):
    from backend.app.demo import media_samples
    from backend.app.media import audio_forensics, video_forensics
    media_samples.make_voicemail(tmp_path / "clean.wav", seed=3, spliced=False)
    media_samples.make_voicemail(tmp_path / "edited.wav", seed=3, spliced=True)
    clean = audio_forensics.analyse(tmp_path / "clean.wav")
    edited = audio_forensics.analyse(tmp_path / "edited.wav")
    assert clean["summary"]["splice_candidates"] == 0
    assert edited["summary"]["splice_candidates"] >= 1
    assert any("Audacity" in i for i in edited["artifacts"][0]["indicators"])
    if media_samples.make_cctv_clip(tmp_path / "clip.mp4").get("created"):
        v = video_forensics.analyse(tmp_path / "clip.mp4")
        if v["summary"]["opencv_available"]:
            assert v["summary"]["duplicate_runs"] >= 1 and v["summary"]["abrupt_changes"] >= 1


def test_ai_insights_ask_and_iocs():
    with TestClient(app) as c:
        tok = c.post("/api/auth/login", json={"username": "investigator", "password": "forensics123"}).json()["token"]
        H = {"Authorization": f"Bearer {tok}"}
        cid = c.post("/api/demo?seed=33", headers=H).json()["id"]
        ins = c.get(f"/api/cases/{cid}/ai/insights", headers=H).json()
        assert ins["attack_chain"] and ins["attack_chain"][0]["tactic"] == "Initial Access"
        assert ins["verification"]["verified"] == ins["verification"]["statements"]
        assert all(s["status"] == "verified" for s in ins["summary"])
        ans = c.post(f"/api/cases/{cid}/ai/ask", headers=H, json={"question": "Did the attacker log in with the decoy credential?"}).json()
        assert ans["answer"] and ans["answer"][0]["status"] == "verified"
        csv = c.get(f"/api/cases/{cid}/iocs.csv?token={tok}").text
        assert csv.startswith("type,value") and len(csv.splitlines()) > 3
        layers = c.get(f"/api/cases/{cid}/layers", headers=H).json()
        assert layers["media"]["audio"] == 1
