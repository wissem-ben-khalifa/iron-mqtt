// Fleet panel: one table row per device from GET /fleet/overview, updated in place.
// Status comes from the device's heartbeat (sent every 60 s, and at once on pause/resume),
// not from whether it happened to send telemetry: a camera between bursts is Idle, not down.

import { el, replace, stateMessage } from "./dom.js";
import { MISSING, ago, deviceType, isNum, plural, rate } from "./format.js";

const HEARTBEAT_S = 60;
const OFFLINE_AFTER_S = HEARTBEAT_S * 2.5;

export function deviceStatus(d, now = Date.now()) {
  const beat = new Date(d.last_heartbeat || d.last_seen || NaN).getTime();
  if (d.state === "offline") return { tone: "off", shape: "ring", word: "Offline", key: "offline" };
  if (!Number.isFinite(beat) || (now - beat) / 1000 > OFFLINE_AFTER_S) {
    return { tone: "crit", shape: "square", word: "No heartbeat", key: "offline" };
  }
  if (d.paused) return { tone: "warn", shape: "ring-gap", word: "Paused", key: "paused" };
  if (isNum(d.rate?.genuine_per_s) && d.rate.genuine_per_s > 0) return { tone: "good", shape: "dot", word: "Sending", key: "sending" };
  return { tone: "off", shape: "bar", word: "Idle", key: "idle" };
}

export function summarize(devices, now = Date.now()) {
  const keys = devices.map((d) => deviceStatus(d, now).key);
  const count = (k) => keys.filter((x) => x === k).length;
  return { total: devices.length, reporting: devices.length - count("offline"), paused: count("paused"),
    sending: count("sending"), idle: count("idle") };
}

export function createFleet(container, note) {
  const rows = new Map();
  let tbody = null;

  function buildRow(id) {
    const r = {
      shape: el("span", { class: "shape", "aria-hidden": "true" }),
      word: el("span", { class: "status-word" }),
      type: el("td"), beat: el("td", { class: "num" }), last: el("td", { class: "num" }),
      rate: el("td", { class: "num" }), flag: el("td", { class: "flag-cell" }),
    };
    r.node = el("tr", null,
      el("th", { scope: "row", class: "dev-id" }, el("span", { title: id, translate: "no" }, id)),
      r.type,
      el("td", null, el("span", { class: "det" }, r.shape, r.word)),
      r.beat, r.last, r.rate, r.flag);
    return r;
  }

  function setStatus(r, st) {
    const write = () => {
      r.shape.dataset.tone = st.tone;
      r.shape.dataset.shape = st.shape;
      r.word.dataset.tone = st.tone;
      r.word.textContent = st.word;
    };
    if (r.status && r.status.word !== st.word) {
      r.shape.style.opacity = "0";
      requestAnimationFrame(() => { write(); r.shape.style.opacity = "1"; });
    } else write();
    r.status = st;
  }

  function render(overview) {
    const devices = Array.isArray(overview?.devices) ? overview.devices : [];
    note.textContent = isNum(overview?.window_s)
      ? `Status from each device’s heartbeat; rates over the last ${overview.window_s} s.` : "Status from each device’s heartbeat.";
    if (devices.length === 0) {
      rows.clear();
      tbody = null;
      replace(container, stateMessage("No devices have reported yet. Start the range with ./iron up, then wait one heartbeat (60 s)."));
      return;
    }
    if (!tbody || !container.contains(tbody)) {
      tbody = el("tbody");
      replace(container, el("div", { class: "table-wrap panel-body" }, el("table", { class: "fleet-table" },
        el("caption", { class: "visually-hidden" }, "Devices"),
        el("thead", null, el("tr", null,
          el("th", { scope: "col" }, "Device"), el("th", { scope: "col" }, "Type"), el("th", { scope: "col" }, "Status"),
          el("th", { scope: "col", class: "num" }, "Heartbeat"), el("th", { scope: "col", class: "num" }, "Last message"),
          el("th", { scope: "col", class: "num" }, "Rate"), el("th", { scope: "col" }, el("span", { class: "visually-hidden" }, "Warnings")))),
        tbody)));
    }
    const now = Date.now();
    const seen = new Set();
    for (const [i, d] of devices.entries()) {
      const id = typeof d._id === "string" && d._id ? d._id : `Unnamed device ${i + 1}`;
      seen.add(id);
      let r = rows.get(id);
      if (!r) { r = buildRow(id); rows.set(id, r); }
      setStatus(r, deviceStatus(d, now));
      replace(r.type, d.type ? deviceType(d.type) : "Type not reported",
        el("span", { class: "sub" }, d.profile_version ? `Profile ${d.profile_version}` : "Profile not reported"));
      r.beatAt = d.last_heartbeat || null;
      r.lastAt = d.last_seen || null;
      r.beat.textContent = r.beatAt ? ago(r.beatAt, now) : MISSING;
      r.last.textContent = r.lastAt ? ago(r.lastAt, now) : MISSING;
      r.rate.textContent = rate(d.rate?.genuine_per_s);
      const unverified = d.rate?.unverified_per_s;
      if (isNum(unverified) && unverified > 0) {
        replace(r.flag, el("span", { class: "det flag", title: "Messages on this device’s topic without a genuine device envelope" },
          el("span", { class: "shape", dataset: { tone: "crit", shape: "square" }, "aria-hidden": "true" }),
          `Unverified ${rate(unverified)}`));
      } else r.flag.replaceChildren();
    }
    for (const id of [...rows.keys()]) if (!seen.has(id)) rows.delete(id);
    tbody.replaceChildren(...[...rows.entries()].sort(([a], [b]) => a.localeCompare(b, "en", { numeric: true })).map(([, r]) => r.node));
    tbody.closest("table").setAttribute("aria-label", plural(devices.length, "device", "devices"));
  }

  function tick() {
    const now = Date.now();
    for (const r of rows.values()) {
      if (r.beatAt) r.beat.textContent = ago(r.beatAt, now);
      if (r.lastAt) r.last.textContent = ago(r.lastAt, now);
    }
  }

  function showError(err) {
    if (!tbody) replace(container, stateMessage(`Could not load the fleet: ${err.detail || err.message}. Retrying.`, "crit"));
  }

  return { render, tick, showError };
}
