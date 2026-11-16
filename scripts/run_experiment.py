"""Generate one labelled experiment run: benign warm-up, then timed attack(s), then cool-down.

Captures the broker's traffic for the whole run (the sensor is always on; this just records
the window), launches floods through the API at known times, and writes a run manifest with
exact attack start/stop per source IP so ids/labeling.py can label feature windows as
benign/attack WITHOUT the detector. Produces a self-contained pcap for the run.

    python -m scripts.run_experiment --name train-A --warmup 120 --attacks 1000:60,5000:60 --cooldown 60
Each attack is RATE:DURATION (msgs/s : seconds), run back to back with a gap.
Runs on the HOST (needs docker + the API). Writes captures/runs/<name>/.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import urllib.request

ATTACKER_SRC_IP = "172.28.0.40"
ROOT = Path(__file__).resolve().parent.parent


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token() -> str:
    return subprocess.check_output(
        ["bash", "-c", "grep '^API_TOKEN=' .env | cut -d= -f2"], cwd=ROOT, text=True).strip()


class Api:
    """Minimal stdlib HTTP client (host python has no httpx)."""

    def __init__(self):
        self.base = "http://localhost:8000"
        self.headers = {"Authorization": f"Bearer {_token()}", "Content-Type": "application/json"}

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=self.headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def get(self, path):
        return self._call("GET", path)

    def post(self, path, json=None):
        return self._call("POST", path, json)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--warmup", type=float, default=120, help="benign seconds before the first attack")
    ap.add_argument("--attacks", default="2000:60", help="comma list of RATE:DURATION")
    ap.add_argument("--gap", type=float, default=45, help="benign seconds between/after attacks")
    ap.add_argument("--cooldown", type=float, default=60)
    ap.add_argument("--qos", type=int, default=0)
    args = ap.parse_args()

    out = ROOT / "captures" / "runs" / args.name
    out.mkdir(parents=True, exist_ok=True)
    attacks_spec = [(float(r), float(d)) for r, d in (a.split(":") for a in args.attacks.split(","))]

    manifest = {"name": args.name, "profile_version": None, "started_at": now_iso(),
                "broker_port": 8883, "attacker_src_ip": ATTACKER_SRC_IP, "attacks": []}
    t0 = time.time()
    api = Api()
    if True:
        manifest["profile_version"] = (api.get("/devices")[0] or {}).get("profile_version")
        print(f"[{args.name}] warm-up {args.warmup:.0f}s benign ...")
        time.sleep(args.warmup)
        for i, (rate, duration) in enumerate(attacks_spec, 1):
            start = now_iso()
            print(f"[{args.name}] attack {i}: {rate}/s for {duration:.0f}s (qos {args.qos})")
            api.post("/attacks/flood", json={"rate_per_s": rate, "duration_s": duration, "qos": args.qos})
            time.sleep(duration)
            agent = api.post("/attacks/stop")
            end = now_iso()
            manifest["attacks"].append({
                "src_ip": ATTACKER_SRC_IP, "rate_per_s": rate, "qos": args.qos,
                "start": start, "end": end, "sent": agent.get("sent"),
                "achieved_rate_per_s": agent.get("actual_rate_per_s")})
            print(f"[{args.name}] attack {i} done: sent {agent.get('sent')}")
            time.sleep(args.gap)
        print(f"[{args.name}] cool-down {args.cooldown:.0f}s ...")
        time.sleep(args.cooldown)
    manifest["ended_at"] = now_iso()

    # Collect the capture chunks that overlap this run and merge them into one pcap.
    lo = t0 - 10
    chunks = [p for p in sorted(glob.glob(str(ROOT / "captures/live/*.pcap")))
              if os.path.getmtime(p) >= lo]
    container_paths = [f"/captures/{Path(p).relative_to(ROOT / 'captures')}" for p in chunks]
    uid = f"{os.getuid()}:{os.getgid()}"
    subprocess.run(["docker", "run", "--rm", "--user", uid, "-v", f"{ROOT}/captures:/captures",
                    "iron-mqtt/netutils", "mergecap", "-w", f"/captures/runs/{args.name}/run.pcap",
                    *container_paths], check=True)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"[{args.name}] merged {len(chunks)} chunks -> {out}/run.pcap")
    print(f"[{args.name}] manifest: {len(manifest['attacks'])} attacks, profile {manifest['profile_version']}")


if __name__ == "__main__":
    main()
