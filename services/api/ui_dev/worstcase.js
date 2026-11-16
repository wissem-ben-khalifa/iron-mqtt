// DEV ONLY (served solely when the API runs with DEV_UI=1). break-ui worst-case fixtures:
// swaps the console's data source at its single boundary (api.js), never inside a component.
// States: Live data / Worst case / Empty / 30 devices / API down. Kept in the URL (?data=...).

import { ApiError, directRequest as request } from "/ui/js/api.js";

const STATES = [["live", "Live data"], ["worst", "Worst case"], ["empty", "Empty"], ["thirty", "30 devices"], ["down", "API down"]];
const now = () => Date.now();
const iso = (ms) => new Date(ms).toISOString();

function device(id, extra = {}) {
  const t = now() - 4000;
  return { _id: id, type: "env_sensor", profile_version: "p1", state: "online", paused: false,
    last_seen: iso(t), last_heartbeat: iso(t - 20_000), rate: { genuine_per_s: 0.2, unverified_per_s: 0 }, ...extra };
}

function worstDevices() {
  return [
    device("device-01"),
    // The compromised identity during a 20,000 msg/s flood.
    device("device-07", { rate: { genuine_per_s: 0.2, unverified_per_s: 19972.7 } }),
    // Beyond the schema (ids are validated as device-NN), to prove the layout survives it.
    device("device-12-basement-north-ventilation-controller", { type: "smart_plug" }),
    // Just registered: no type, no profile, no heartbeat yet.
    { _id: "device-13", state: "online", rate: { genuine_per_s: 0, unverified_per_s: 0 } },
    device("device-14", { last_heartbeat: "1970-01-01T00:00:00Z", last_seen: "1970-01-01T00:00:00Z" }),
    device("device-15", { last_heartbeat: iso(now() + 120_000), last_seen: iso(now() + 120_000) }), // clock skew
    device("device-16", { paused: true, rate: { genuine_per_s: 0, unverified_per_s: 0 } }),
    device("device-17", { state: "offline", rate: { genuine_per_s: 0, unverified_per_s: 0 } }),
    device("device-18", { type: "industrial_vibration_sensor", rate: { genuine_per_s: 1234.567, unverified_per_s: 0 } }),
    device("device-19", { rate: { genuine_per_s: 1, unverified_per_s: 1 } }), // exactly 1 everywhere
    { type: "camera", state: "online", last_heartbeat: iso(now() - 5000), rate: {} }, // no _id at all
    device("device-20", { type: "door_sensor", rate: { genuine_per_s: 0, unverified_per_s: 0 } }),
  ];
}

function thirtyDevices() {
  const types = ["env_sensor", "smart_plug", "door_sensor", "camera"];
  return Array.from({ length: 30 }, (_, i) => device(`device-${String(i + 1).padStart(2, "0")}`, {
    type: types[i % 4], rate: { genuine_per_s: [0.2, 0.1, 0, 2][i % 4], unverified_per_s: 0 } }));
}

function worstIncidents() {
  const base = now();
  const list = [
    { _id: "a1", kind: "ml_flood", status: "open", detected_at: iso(base - 3000),
      source: { src_ip: "2001:db8:85a3:8d3:1319:8a2e:370:7348", device_id: "device-12-basement-north-ventilation-controller" },
      window: { start: iso(base - 40_000), end: iso(base - 5000) },
      detector: { name: "live", model_version: "m0003-robust-prefer-retrained-after-poisoning-test", score: 0.99999, ml: true },
      windows: 1284, windows_ml: 1283, windows_threshold_only: 1 },
    { _id: "a2", kind: "threshold_flood", status: "open", detected_at: iso(base - 9000),
      source: { src_ip: "172.28.0.110" }, detector: { score: 0 } },                       // no window, no model
    { _id: "a3", kind: "dns_tunnel_suspect", status: "acknowledged", detected_at: iso(base - 12_000) }, // unknown kind, no source
    { _id: "a4", kind: "ml_flood", detected_at: null, source: { src_ip: "172.28.0.40" }, detector: {} }, // missing time
  ];
  for (let i = 0; i < 116; i++) {
    list.push({ _id: `b${i}`, kind: "ml_flood", status: "open", detected_at: iso(base - 20_000 - i * 5000),
      source: { src_ip: "172.28.0.40" }, window: { start: iso(base - 25_000 - i * 5000), end: iso(base - 20_000 - i * 5000) },
      detector: { model_version: "m0001", score: 1 }, windows: 1 });
  }
  return list;
}

function worstIncidentDetail() {
  const t = now();
  return {
    _id: "a1", kind: "ml_flood", status: "open", detected_at: iso(t - 3000),
    source: { src_ip: "2001:db8:85a3:8d3:1319:8a2e:370:7348", device_id: "device-12-basement-north-ventilation-controller" },
    window: { start: iso(t - 40_000), end: iso(t - 5000) },
    detector: { model_version: "m0003-robust-prefer-retrained-after-poisoning-test", score: 0.99999, threshold: 13737 },
    windows: 1284, windows_ml: 1283, windows_threshold_only: 1,
    ground_truth: { run_id: "run-20261016T180518", mismatch: true },
    evidence: { pcap: "/captures/live/20261016T141537-very-long-archive-name-after-an-overnight-rotation-and-copy-to-evidence.pcap" },
    trigger: { window_start: iso(t - 40_000), window_end: iso(t - 35_000), score: 0.99999, ml: true, threshold_hit: true,
      features: { payload_up: 1234567890, iat_up_min: 0.0000004, conns: 1, rst_any: 1, syn_up: 0,
        bytes_ratio_up_down: 1234.5, active_s: 4.999, pkts_up: 1, entropy_payload_bits: 7.9, payload_up_mean: null } },
  };
}

function worstSeries() {
  const t = Math.floor(now() / 10_000) * 10_000;
  const b = [];
  for (let i = 30; i >= 0; i--) {
    if (i === 12 || i === 13) continue; // a gap
    const flood = i <= 8 && i >= 3;
    b.push({ t: iso(t - i * 10_000), p50_ms: i === 20 ? null : flood ? 1600 : 0.71, p95_ms: flood ? 20000 : i === 25 ? 0 : 0.95,
      messages: i === 5 ? 1 : 9, rate_per_s: flood ? 0.1 : 0.9 });
  }
  return { buckets: b };
}

function worstRuns() {
  const t = now();
  return [
    { _id: "run-a", attacks: [{ started_at: iso(t - 90_000), planned_end: iso(t - 30_000), rate_per_s: 20000 }] },
    { _id: "run-b", attacks: [{ started_at: iso(t - 70_000), planned_end: iso(t - 50_000), rate_per_s: 500 }] }, // overlaps run-a
    { _id: "run-c", attacks: [{ started_at: iso(t - 4000), rate_per_s: 2000 }] },                               // still running
    { _id: "run-d", attacks: [{ started_at: iso(t - 200_000), planned_end: iso(t - 199_000), rate_per_s: 2000 }] }, // 1 s
  ];
}

function fixtureSource(mode) {
  return async (method, path, body) => {
    if (mode === "down") throw new ApiError(0, "The API is unreachable.");
    const p = path.split("?")[0];
    if (p === "/features/catalog") return request(method, path, body);
    if (p === "/results/summary") {
      if (mode === "empty") return {};
      const real = await request(method, path, body);
      if (mode === "worst") {
        real.detectors.rows[3] = { ...real.detectors.rows[3], name: "Suricata 8.0.7, all rules, full inspection, midstream pickup on, encryption-handling full", fp_per_hour: 1234.5, f1: null };
      }
      return real;
    }
    if (p === "/fleet/overview") return { window_s: 15, devices: mode === "empty" ? [] : mode === "thirty" ? thirtyDevices() : worstDevices() };
    if (p === "/detector/status") return mode === "empty" ? { model_version: null, windows_last_30s: 0 } : { model_version: "m0003-robust-prefer-retrained-after-poisoning-test", windows_last_30s: 1284, last_incident_at: iso(now() - 3000) };
    if (p === "/telemetry/series") return mode === "empty" ? { buckets: [] } : worstSeries();
    if (p === "/runs") return mode === "empty" ? [] : worstRuns();
    if (p === "/incidents") return mode === "empty" ? [] : worstIncidents();
    if (/^\/incidents\/[^/]+\/windows$/.test(p)) {
      return { windows: Array.from({ length: 300 }, (_, i) => ({ start: iso(now() - 40_000 + i * 5000),
        verdict: i % 7 ? { label: "attack", score: 1 } : { label: "benign", score: 0.0131 }, features: { payload_up: i % 7 ? 1699830 : 123978 } })) };
    }
    if (/^\/incidents\/[^/]+$/.test(p)) return worstIncidentDetail();
    if (p === "/fleet/commands") return { sent_at: iso(now()) };
    if (p === "/attacks/flood") throw new ApiError(409, "a flood is already running");
    if (p === "/attacks/status") return { state: "done", sent: 0 };
    if (p === "/attacks/stop") return { state: "done", sent: 599186, actual_rate_per_s: 19972.7, gen_seconds: 30 };
    throw new ApiError(404, `No fixture for ${path}`);
  };
}

export function install({ setDataSource, refreshAll, restartLive, latency }) {
  const params = new URLSearchParams(location.search);
  let mode = STATES.some(([k]) => k === params.get("data")) ? params.get("data") : "live";

  const bar = document.createElement("div");
  bar.className = "dev-toggle";
  bar.setAttribute("role", "group");
  bar.setAttribute("aria-label", "Development data source (DEV_UI only)");
  const buttons = STATES.map(([key, label]) => {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", () => apply(key));
    bar.append(b);
    return [key, b];
  });

  function apply(next) {
    mode = next;
    for (const [k, b] of buttons) b.setAttribute("aria-pressed", String(k === mode));
    const url = new URL(location.href);
    if (mode === "live") url.searchParams.delete("data"); else url.searchParams.set("data", mode);
    history.replaceState(null, "", url);
    setDataSource(mode === "live" ? null : fixtureSource(mode));
    latency.reset();
    refreshAll();
    restartLive();
  }

  const style = document.createElement("link");
  style.rel = "stylesheet";
  style.href = "/ui-dev/worstcase.css";
  document.head.append(style);
  document.body.append(bar);
  for (const [k, b] of buttons) b.setAttribute("aria-pressed", String(k === mode));
  if (mode !== "live") setDataSource(fixtureSource(mode));
}
