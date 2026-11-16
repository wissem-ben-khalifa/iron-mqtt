// Console entry point: unlock, polling, live stream, and wiring between panels.

import { ApiError, get, setDataSource, token, usingFixtures } from "./api.js";
import { createControls } from "./controls.js";
import { createFleet, summarize } from "./fleet.js";
import { clock } from "./format.js";
import { FEED_WINDOW_MIN, createDetail, createFeed } from "./incidents.js";
import { createLatency } from "./latency.js";
import { connectLive } from "./live.js";
import { renderResults, resultsError } from "./results.js";
import { createStatusBar } from "./status.js";

const $ = (id) => document.getElementById(id);
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const RETRY_S = 5;

const bar = createStatusBar();
const fleet = createFleet($("fleet"), $("fleet-note"));
const latency = createLatency($("latency"), $("latency-note"));
const feed = createFeed($("incidents"), { onOpen: openIncident, reducedMotion });
let featureCatalog = new Map();
const detail = createDetail($("incident-detail"), { onClose: () => feed.select(null), catalog: () => featureCatalog });
const controls = createControls($("controls"), $("confirm-flood"), { onRunChange: () => refresh.runs() });

let live = null;
let started = false;
let unreachableSince = null;
const timers = [];

function openIncident(id, trigger) {
  feed.select(id);
  detail.open(id, trigger);
}

// ---------------------------------------------------------------------------- errors
function banner(text) {
  const b = $("banner");
  if (!text) { b.hidden = true; b.replaceChildren(); return; }
  b.replaceChildren();
  const shape = document.createElement("span");
  shape.className = "shape";
  shape.dataset.tone = "crit";
  shape.dataset.shape = "square";
  shape.setAttribute("aria-hidden", "true");
  b.append(shape, document.createTextNode(text));
  b.hidden = false;
}

function ok() {
  if (unreachableSince) {
    unreachableSince = null;
    banner(null);
    document.querySelectorAll(".panel[data-stale]").forEach((p) => p.removeAttribute("data-stale"));
  }
}

function failed(err, panel) {
  if (err instanceof ApiError && err.status === 401) { lock("The token was rejected. Enter the API token from .env."); return true; }
  if (err instanceof ApiError && err.status === 0) {
    if (!unreachableSince) unreachableSince = new Date();
    banner(`API unreachable since ${clock(unreachableSince)}. Showing the last data received. Retrying every ${RETRY_S} s.`);
    document.querySelectorAll(".panel").forEach((p) => p.setAttribute("data-stale", ""));
    for (const what of ["devices", "model", "incident"]) bar.unknown(what);
    panel?.(err); // panels that never loaded say so; loaded panels keep their last render
    return true;
  }
  panel?.(err);
  return false;
}

// ---------------------------------------------------------------------------- data loads
const refresh = {
  async fleet() {
    try {
      const o = await get("/fleet/overview");
      fleet.render(o);
      const summary = summarize(o.devices || []);
      bar.devices(summary);
      controls.setFleet(summary);
      ok();
    }
    catch (err) { failed(err, fleet.showError); }
  },
  async detector() {
    try { const s = await get("/detector/status"); bar.detector(s); bar.lastIncident(s.last_incident_at); ok(); }
    catch (err) { failed(err); }
  },
  async latency() {
    try { latency.merge(await get(latency.query())); ok(); }
    catch (err) { failed(err, latency.showError); }
  },
  async runs() {
    try { latency.setRuns(await get("/runs?limit=20")); ok(); }
    catch (err) { failed(err); }
  },
  async incidents() {
    const since = new Date(Date.now() - FEED_WINDOW_MIN * 60_000).toISOString();
    try { feed.load(await get(`/incidents?since=${encodeURIComponent(since)}&limit=100`)); ok(); }
    catch (err) { failed(err, feed.showError); }
  },
  async catalog() {
    try { featureCatalog = new Map((await get("/features/catalog")).map((f) => [f.name, f])); ok(); }
    catch (err) { failed(err); }
  },
  async results() {
    try { renderResults($("results"), $("results-note"), await get("/results/summary")); ok(); }
    catch (err) { failed(err, (e) => resultsError($("results"), e)); }
  },
};

function every(seconds, fn) {
  fn();
  timers.push(setInterval(() => { if (!document.hidden) fn(); }, seconds * 1000));
}

async function start() {
  if (started) return;
  started = true;
  $("lockscreen").hidden = true;
  $("main").inert = false;
  every(5, refresh.fleet);
  every(5, refresh.detector);
  every(10, refresh.latency);
  every(10, refresh.runs);
  refresh.incidents();
  refresh.results();
  refresh.catalog();
  timers.push(setInterval(() => { fleet.tick(); bar.tick(); }, 1000));
  document.addEventListener("visibilitychange", () => { if (!document.hidden) { refresh.fleet(); refresh.latency(); } });
  startLive();
}

function startLive() {
  live?.close();
  if (usingFixtures()) { bar.live({ state: "fixtures" }); return; }
  live = connectLive({
    onIncident: (inc, op) => {
      feed.upsert(inc, op);
      if (op === "insert" && inc.kind !== "test") {
        bar.lastIncident(inc.detected_at);
        $("incident-announcer").textContent = `New incident at ${clock(inc.detected_at)} from ${inc?.source?.src_ip || "an unknown source"}.`;
      }
    },
    onState: (s) => {
      bar.live(s);
      if (s.state === "connected") refresh.incidents(); // catch anything missed while disconnected
      if (s.state === "rejected") lock("The live feed rejected the token. Enter the API token from .env.");
    },
  });
}

// ---------------------------------------------------------------------------- lock / unlock
function lock(message) {
  token.clear();
  if (started) { location.reload(); return; } // a clean page, nothing left on screen
  showLockscreen(message);
}

function showLockscreen(message) {
  $("lockscreen").hidden = false;
  $("main").inert = true;
  $("unlock-error").textContent = message || "";
  bar.live({ state: "locked" });
  $("token").focus();
}

$("lock").addEventListener("click", () => lock());

$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const value = $("token").value.trim();
  if (!value) return;
  token.set(value);
  const submit = e.submitter || $("unlock-form").querySelector("button");
  submit.disabled = true;
  submit.textContent = "Checking…";
  $("unlock-error").textContent = "";
  try {
    await get("/devices");
    $("token").value = "";
    $("unlock-error").textContent = "";
    start();
  } catch (err) {
    token.clear();
    $("unlock-error").textContent = err.status === 401 ? "That token was rejected. Copy API_TOKEN from .env and try again."
      : err.status === 0 ? "The API is unreachable. Check that the range is running (./iron up)." : `Could not check the token: ${err.detail || err.message}.`;
    $("token").focus();
  } finally {
    submit.disabled = false;
    submit.textContent = "Unlock";
  }
});

// ---------------------------------------------------------------------------- boot
async function boot() {
  let config = null;
  try { config = await get("/ui-config"); }
  catch { config = null; }
  if (config) controls.render(config.flood_scenario);
  else controls.showError(new ApiError(0, "The API is unreachable"));
  if (config?.dev_ui) {
    // Dev only: served solely when the API runs with DEV_UI=1.
    const dev = await import("/ui-dev/worstcase.js");
    dev.install({ setDataSource, refreshAll: () => Object.values(refresh).forEach((f) => f()), restartLive: startLive, latency, controls, config });
  }
  if (token.get() || usingFixtures()) start();
  else showLockscreen();
}

boot();
