"""Console checks: the /ui mount, its security headers, /results/summary, and the read-only
endpoints the console uses. Runs against the live range (api:8000)."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx
import pytest

pytestmark = pytest.mark.skipif("API_URL" not in os.environ, reason="needs the running range")

API = os.environ.get("API_URL", "")
TOKEN = os.environ.get("API_TOKEN", "")
H = {"Authorization": f"Bearer {TOKEN}"}
SUMMARY = Path("/app/docs/results/summary.json")
UI_FILES = ["/ui/", "/ui/styles.css", "/ui/favicon.svg", "/ui/js/main.js", "/ui/js/api.js", "/ui/js/live.js",
            "/ui/js/dom.js", "/ui/js/format.js", "/ui/js/fleet.js", "/ui/js/latency.js", "/ui/js/incidents.js",
            "/ui/js/results.js", "/ui/js/status.js", "/ui/js/controls.js"]


@pytest.fixture(scope="module")
def api():
    with httpx.Client(base_url=API, timeout=15) as client:
        yield client


def test_ui_redirects_and_serves_the_console(api):
    r = api.get("/ui", follow_redirects=False)
    assert r.status_code in (301, 302, 307, 308) and r.headers["location"].endswith("/ui/")
    page = api.get("/ui/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    assert "IRON-MQTT range" in page.text


def test_ui_sets_a_strict_csp(api):
    r = api.get("/ui/")
    csp = r.headers.get("content-security-policy", "")
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert r.headers.get("x-content-type-options") == "nosniff"


def test_ui_files_load_with_the_right_types_and_never_contain_the_token(api):
    for path in UI_FILES:
        r = api.get(path)
        assert r.status_code == 200, path
        assert TOKEN not in r.text, f"token found in {path}"
        if path.endswith(".js"):
            assert "javascript" in r.headers["content-type"], path
    font = api.get("/ui/fonts/IBMPlexSans-Regular.woff2")
    assert font.status_code == 200 and font.headers["content-type"] == "font/woff2"


def test_ui_never_uses_innerhtml_or_external_origins(api):
    for path in UI_FILES:
        text = api.get(path).text
        # Actual use, not mentions in comments.
        assert not re.search(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write", text), path
        assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", text), f"external URL in {path}"


def test_dev_worst_case_toggle_is_not_served_by_default(api):
    assert api.get("/ui-config").json()["dev_ui"] is False
    assert api.get("/ui-dev/worstcase.js").status_code == 404


def test_results_summary_requires_auth(api):
    assert api.get("/results/summary").status_code == 401


def test_results_summary_serves_the_committed_file_unchanged(api):
    r = api.get("/results/summary", headers=H)
    assert r.status_code == 200
    served = r.json()
    assert served == json.loads(SUMMARY.read_text())
    ids = {row["id"] for row in served["detectors"]["rows"]}
    assert {"ml", "threshold", "suricata-default", "suricata-full"} <= ids
    assert {row["id"] for row in served["robust_models"]["rows"]} >= {"m0001", "m0002", "m0003", "m0006"}
    for row in served["detectors"]["rows"] + served["robust_models"]["rows"]:
        for k in ("precision", "recall", "f1", "fp_per_hour"):
            assert isinstance(row[k], (int, float)), (row["id"], k)


@pytest.mark.parametrize("path", ["/fleet/overview", "/telemetry/series", "/detector/status"])
def test_console_endpoints_require_auth_and_answer(api, path):
    assert api.get(path).status_code == 401
    r = api.get(path, headers=H)
    assert r.status_code == 200, r.text


def test_fleet_overview_shape(api):
    o = api.get("/fleet/overview", headers=H).json()
    assert o["window_s"] == 15 and isinstance(o["devices"], list)
    for d in o["devices"]:
        assert set(d["rate"]) == {"genuine_per_s", "unverified_per_s"}


def test_telemetry_series_shape_and_since(api):
    s = api.get("/telemetry/series", headers=H, params={"minutes": 5, "bucket_s": 10}).json()
    for b in s["buckets"]:
        assert {"t", "p50_ms", "p95_ms", "messages", "rate_per_s"} <= set(b)
    if s["buckets"]:
        later = api.get("/telemetry/series", headers=H, params={"since": s["buckets"][-1]["t"]}).json()
        assert all(b["t"] >= s["buckets"][-1]["t"] for b in later["buckets"])


def test_incident_windows_404_for_unknown_incident(api):
    assert api.get("/incidents/000000000000000000000000/windows", headers=H).status_code == 404


def test_feature_catalog_has_labels_units_and_provenance(api):
    assert api.get("/features/catalog").status_code == 401
    cat = api.get("/features/catalog", headers=H).json()
    by = {f["name"]: f for f in cat}
    assert len(by) == 19
    assert all(f["label"] and f["provenance"] in {"device", "partial", "system"} for f in cat)
    assert by["payload_up"]["provenance"] == "device" and by["pkts_down"]["provenance"] == "partial"
    assert by["pkts_up"]["unit"] == ["packet", "packets"]          # plural-aware units
    assert by["bytes_ratio_up_down"]["unit"] is None               # a plain ratio


def _fleet_paused(api):
    devices = api.get("/fleet/overview", headers=H).json()["devices"]
    return [d.get("paused") for d in devices if d.get("last_heartbeat")]


def _wait_for(api, want_all_paused: bool, timeout_s: float = 8.0) -> list:
    import time
    deadline = time.time() + timeout_s
    states = _fleet_paused(api)
    while time.time() < deadline:
        if states and all(s is want_all_paused for s in states):
            break
        time.sleep(0.5)
        states = _fleet_paused(api)
    return states


def test_pause_and_resume_are_reported_by_the_devices(api):
    assert api.post("/fleet/commands", headers=H, json={"cmd": "pause"}).status_code == 202
    try:
        states = _wait_for(api, True)
        assert states and all(states), states
    finally:
        api.post("/fleet/commands", headers=H, json={"cmd": "resume"})
    states = _wait_for(api, False)
    assert states and not any(states), states
