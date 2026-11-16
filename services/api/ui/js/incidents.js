// Incident feed (live from the WebSocket) and the incident detail drawer.

import { get } from "./api.js";
import { el, replace, stateMessage, status } from "./dom.js";
import { MISSING, clock, durationBetween, featureValue, humanize, isNum, num, parseTime, percent, plural, seconds } from "./format.js";

const PROVENANCE = { device: "Device", partial: "Partial", system: "System" };

export const FEED_WINDOW_MIN = 10;
const MAX_ROWS = 200;
const DETECTORS = { ml_flood: "ML", threshold_flood: "Threshold", new_ip_for_cert: "New IP rule" };

export function detectorLabel(inc) {
  return DETECTORS[inc?.kind] || humanize(inc?.kind);
}

function sourceCell(inc) {
  const ip = inc?.source?.src_ip || "Unknown source";
  const dev = inc?.source?.device_id;
  return el("td", { class: "src" }, el("span", { translate: "no" }, ip),
    dev ? el("span", { class: "sub" }, "Device ", el("span", { translate: "no" }, dev)) : el("span", { class: "sub" }, "Device not identified"));
}

export function createFeed(container, { onOpen, reducedMotion }) {
  const rows = new Map(); // id -> { inc, tr }
  let tbody = null;
  let loaded = false;

  function rowFor(inc) {
    const id = inc._id;
    const when = clock(inc.detected_at);
    const open = el("button", { type: "button", class: "row-open",
      "aria-label": `Open incident at ${when} from ${inc?.source?.src_ip || "unknown source"}` }, when);
    const tr = el("tr", { dataset: { id } },
      el("td", null, open),
      sourceCell(inc),
      el("td", null, detectorLabel(inc)),
      el("td", { class: "num" }, isNum(inc?.detector?.score) ? percent(inc.detector.score) : MISSING),
      el("td", { class: "num" }, inc?.window ? durationBetween(inc.window.start, inc.window.end) : MISSING),
      el("td", { translate: inc?.detector?.model_version ? "no" : null }, inc?.detector?.model_version || "Rule"));
    tr.addEventListener("click", () => onOpen(id, open));
    return tr;
  }

  function ensureTable() {
    if (tbody && container.contains(tbody)) return;
    tbody = el("tbody");
    replace(container, el("div", { class: "table-wrap panel-body" }, el("table", { class: "feed" },
      el("caption", { class: "visually-hidden" }, "Incidents, newest first"),
      el("thead", null, el("tr", null,
        el("th", { scope: "col" }, "Time"), el("th", { scope: "col" }, "Source"), el("th", { scope: "col" }, "Detector"),
        el("th", { scope: "col", class: "num" }, "Peak ML score"), el("th", { scope: "col", class: "num" }, "Duration"),
        el("th", { scope: "col" }, "Model"))), tbody)));
  }

  function renderEmpty() {
    tbody = null;
    replace(container, stateMessage(`No incidents in the last ${FEED_WINDOW_MIN} minutes.`));
  }

  function sorted() {
    return [...rows.values()].sort((a, b) => (parseTime(b.inc.detected_at) ?? 0) - (parseTime(a.inc.detected_at) ?? 0));
  }

  function load(list) {
    rows.clear();
    for (const inc of Array.isArray(list) ? list : []) {
      if (!inc?._id || inc.kind === "test") continue;
      rows.set(inc._id, { inc, tr: rowFor(inc) });
    }
    loaded = true;
    if (rows.size === 0) { renderEmpty(); return; }
    ensureTable();
    tbody.replaceChildren(...sorted().slice(0, MAX_ROWS).map((r) => r.tr));
  }

  // Live insert or update from the change stream.
  function upsert(inc, op) {
    if (!inc?._id || inc.kind === "test") return;
    const existing = rows.get(inc._id);
    const tr = rowFor(inc);
    if (existing?.tr.getAttribute("aria-selected") === "true") tr.setAttribute("aria-selected", "true");
    rows.set(inc._id, { inc, tr });
    ensureTable();
    if (existing && existing.tr.isConnected) existing.tr.replaceWith(tr);
    else tbody.prepend(tr);
    while (tbody.children.length > MAX_ROWS) tbody.lastElementChild.remove();
    if (op === "insert" && !existing && !reducedMotion()) {
      tr.classList.add("arriving");
      requestAnimationFrame(() => requestAnimationFrame(() => tr.classList.remove("arriving")));
    }
  }

  function select(id) {
    for (const { tr } of rows.values()) tr.setAttribute("aria-selected", tr.dataset.id === id ? "true" : "false");
  }

  function showError(err) {
    if (!loaded) replace(container, stateMessage(`Could not load incidents: ${err.detail || err.message}. Retrying.`, "crit"));
  }

  return { load, upsert, select, showError, latest: () => sorted()[0]?.inc ?? null };
}

// ---------------------------------------------------------------------------- detail drawer

export function createDetail(dialog, { onClose, catalog }) {
  let returnFocus = null;

  function close() { if (dialog.open) dialog.close(); }
  dialog.addEventListener("close", () => { onClose(); returnFocus?.focus?.(); });
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close(); }); // click on the backdrop

  function head(title) {
    return el("div", { class: "dialog-head" },
      el("h2", { id: "detail-title" }, title),
      el("button", { type: "button", class: "btn btn-quiet", onclick: close }, "Close"));
  }

  function facts(pairs) {
    return el("dl", { class: "facts" }, pairs.filter(Boolean).flatMap(([k, v]) => [el("dt", null, k), el("dd", null, v)]));
  }

  function pcapRow(path) {
    if (!path) return MISSING;
    const msg = el("span", { class: "sub", role: "status" });
    const copy = el("button", { type: "button", class: "btn btn-quiet" }, "Copy path");
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(path); msg.textContent = "Copied"; }
      catch { msg.textContent = "Copy failed. Select the path instead."; }
    });
    return el("span", { class: "path" }, el("code", { translate: "no" }, path), copy,
      el("span", { class: "sub" }, "The file name is the chunk’s start time in UTC."), msg);
  }

  function detection(inc) {
    const gt = inc.ground_truth;
    if (!gt) return "Unknown: no recorded flood run matches this source";
    if (gt.mismatch) return "Unknown: the recorded flood run does not match this alert’s timing";
    if (!isNum(inc.detection_latency_s)) return MISSING;
    const lat = inc.detection_latency_s;
    const close = inc.window_close_s;
    return el("span", null, `${seconds(lat)} after the flood started`,
      isNum(close) ? el("span", { class: "sub" },
        `The triggering 5 s window closed ${seconds(close)} after the start; capture rotation and scoring took ${seconds(lat - close)}.`) : null);
  }

  function windowsLine(inc) {
    if (!isNum(inc.windows)) return MISSING;
    if (!isNum(inc.windows_ml)) return num(inc.windows);
    return `${plural(inc.windows, "window", "windows")} (${num(inc.windows_ml)} ML, ${num(inc.windows_threshold_only)} threshold only)`;
  }

  function featureRows(features) {
    const cat = catalog();
    return Object.entries(features || {}).map(([name, value]) => {
      const info = cat.get(name);
      return el("tr", null,
        el("td", null, info?.label || name, el("span", { class: "sub raw", translate: "no" }, name)),
        el("td", null, info ? el("span", { class: "tag", dataset: { prov: info.provenance } }, PROVENANCE[info.provenance] || info.provenance) : MISSING),
        el("td", { class: "num" }, featureValue(value, info ? info.unit : undefined, name)));
    });
  }

  function featuresTable(features, captionText) {
    if (!features || Object.keys(features).length === 0) return stateMessage("This incident has no recorded features.");
    return el("div", { class: "table-wrap" }, el("table", null,
      el("caption", null, captionText),
      el("thead", null, el("tr", null, el("th", { scope: "col" }, "Feature"),
        el("th", { scope: "col" }, "Set by"), el("th", { scope: "col", class: "num" }, "Value"))),
      el("tbody", null, featureRows(features))));
  }

  function timelineTable(windows, triggerStart) {
    if (!Array.isArray(windows) || windows.length === 0) return stateMessage("No scored windows were stored for this incident.");
    const trig = parseTime(triggerStart)?.getTime();
    return el("div", { class: "table-wrap" }, el("table", null,
      el("caption", null, `${plural(windows.length, "window", "windows")} from this source, each scored once by the live detector`),
      el("thead", null, el("tr", null, el("th", { scope: "col" }, "Window start"), el("th", { scope: "col" }, "Verdict"),
        el("th", { scope: "col", class: "num" }, "ML score"), el("th", { scope: "col", class: "num" }, "Payload to the broker"))),
      el("tbody", null, windows.map((w) => {
        const attack = w?.verdict?.label === "attack";
        const isTrigger = trig && parseTime(w.start)?.getTime() === trig;
        return el("tr", { class: isTrigger ? "is-trigger" : null },
          el("td", null, clock(w.start), isTrigger ? el("span", { class: "sub" }, "Raised the alert") : null),
          el("td", null, w?.verdict ? status(attack ? "crit" : "good", attack ? "square" : "dot", attack ? "Attack" : "Benign") : MISSING),
          el("td", { class: "num" }, isNum(w?.verdict?.score) ? percent(w.verdict.score) : MISSING),
          el("td", { class: "num" }, featureValue(w?.features?.payload_up, ["B", "B"])));
      }))));
  }

  async function open(id, trigger) {
    returnFocus = trigger;
    replace(dialog, head("Incident"), el("div", { class: "dialog-body" }, stateMessage("Loading the incident…")));
    if (!dialog.open) dialog.showModal();
    try {
      const [inc, tl] = await Promise.all([get(`/incidents/${encodeURIComponent(id)}`), get(`/incidents/${encodeURIComponent(id)}/windows`)]);
      const d = inc.detector || {};
      const w = inc.window || {};
      const trig = inc.trigger;
      const gt = inc.ground_truth;
      replace(dialog,
        head(`Incident at ${clock(inc.detected_at)}`),
        el("div", { class: "dialog-body" },
          facts([
            ["Detector", detectorLabel(inc)],
            ["Status", inc.status ? inc.status[0].toUpperCase() + inc.status.slice(1) : MISSING],
            ["Source", inc?.source?.src_ip ? el("span", { translate: "no" }, inc.source.src_ip) : "Unknown source"],
            ["Device", inc?.source?.device_id ? el("span", { translate: "no" }, inc.source.device_id) : "Not identified"],
            ["Incident span", w.start ? `${clock(w.start)} to ${clock(w.end)} (${durationBetween(w.start, w.end)})` : MISSING],
            ["Windows", windowsLine(inc)],
            ["Detected", detection(inc)],
            gt && !gt.mismatch ? ["Ground truth", `${gt.run_id}, flood at ${num(gt.rate_per_s)} msg/s from ${clock(gt.flood_started_at)}`] : null,
            ["Model", d.model_version ? el("span", { translate: "no" }, d.model_version) : "Rule, no model"],
            ["Peak ML score", isNum(d.score) ? percent(d.score) : MISSING],
            ["Threshold", isNum(d.threshold) ? `${num(d.threshold)} B per 5 s window` : MISSING],
            ["Evidence pcap", pcapRow(inc?.evidence?.pcap)],
          ]),
          el("h3", null, "Timeline"),
          timelineTable(tl?.windows, trig?.window_start),
          el("h3", null, "Triggering window"),
          trig ? facts([
            ["Window", `${clock(trig.window_start)} to ${clock(trig.window_end)}`],
            ["ML score", isNum(trig.score) ? percent(trig.score) : MISSING],
            ["Flagged by", trig.ml && trig.threshold_hit ? "ML and threshold" : trig.ml ? "ML" : "Threshold only"],
          ]) : el("p", { class: "state-msg", dataset: { tone: "warn" } },
            "Recorded before the 16 Oct detector fix: these features may come from the incident’s last window, not the one that raised it."),
          featuresTable(trig?.features || inc.features, "Feature values of the triggering window. Set by: who controls the value (docs/FEATURES.md)")));
    } catch (err) {
      replace(dialog, head("Incident"), el("div", { class: "dialog-body" },
        stateMessage(`Could not load this incident: ${err.detail || err.message}. Close this panel and select the incident again.`, "crit")));
    }
    dialog.querySelector(".dialog-head .btn")?.focus();
  }

  return { open, close };
}
