// Honest-device latency panel: p50/p95 (ms) and message rate (msg/s) as two stacked charts on
// one shared time axis (never a dual axis), with flood runs from /runs drawn as labelled spans.
// Latency uses a log scale by default (0.5 ms to the next power of ten above the data), so a
// sub-millisecond baseline and a 2,000 ms flood are both readable; a toggle switches to linear.

import { el, replace, stateMessage, svg } from "./dom.js";
import { clock, isNum, ms, num, plural, rate, shortClock } from "./format.js";

export const WINDOW_MIN = 10;
export const BUCKET_S = 10;
const M = { left: 76, right: 108, top: 20, bottom: 24 };
const H_LAT = 200;
const H_RATE = 78;
const LOG_FLOOR_MS = 0.5;
const SCALE_KEY = "iron-mqtt.latency-scale";

function niceMax(v) {
  const max = Math.max(v, 1e-9);
  const pow = 10 ** Math.floor(Math.log10(max));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * pow >= max) return m * pow;
  return 10 * pow;
}

function linearTicks(max, count = 4) {
  const step = niceMax(max / count);
  const out = [];
  for (let v = 0; v <= max + step / 1e6; v += step) out.push(+v.toFixed(10));
  return out;
}

function pathFor(points, x, y, key, bucketMs) {
  let d = "";
  let prev = null;
  for (const p of points) {
    if (!isNum(p[key])) { prev = null; continue; }
    const cmd = prev && p.t - prev.t <= bucketMs * 2.5 ? "L" : "M";
    d += `${cmd}${x(p.t).toFixed(1)},${y(p[key]).toFixed(1)}`;
    prev = p;
  }
  return d;
}

function lineKey(cls) {
  return svg("svg", { width: 18, height: 8, "aria-hidden": "true" },
    svg("line", { x1: 1, y1: 4, x2: 17, y2: 4, class: `series ${cls}` }));
}

function readScale() {
  try { return localStorage.getItem(SCALE_KEY) === "linear" ? "linear" : "log"; } catch { return "log"; }
}

function timeStep(spanMs) {
  if (spanMs <= 3 * 60_000) return 30_000;
  if (spanMs <= 6 * 60_000) return 60_000;
  return 120_000;
}

export function createLatency(container, note) {
  const buckets = new Map();
  let runs = [];
  let focusIndex = -1;
  let loaded = false;
  let width = 0;
  let scale = readScale();

  const legend = el("div", { class: "chart-legend" });
  const scaleButtons = ["log", "linear"].map((s) => el("button", {
    type: "button", class: "seg", "aria-pressed": String(scale === s),
    onclick: () => { scale = s; try { localStorage.setItem(SCALE_KEY, s); } catch { /* per-tab only */ } draw(); },
  }, s === "log" ? "Log scale" : "Linear scale"));
  const scaleControl = el("div", { class: "segmented", role: "group", "aria-label": "Latency axis scale" }, scaleButtons);
  const legendRow = el("div", { class: "chart-head" }, legend, scaleControl);
  const latSvg = svg("svg", { class: "chart", tabindex: 0, role: "img" });
  const rateTitle = el("p", { class: "chart-title" }, "Honest-device message rate");
  const rateSvg = svg("svg", { class: "chart", "aria-hidden": "true" });
  const caption = el("p", { class: "chart-caption" });
  const tooltip = el("div", { class: "tooltip", hidden: true, role: "presentation" });
  const tableBody = el("tbody");
  const table = el("details", { class: "data-toggle" }, el("summary", null, "Show the data as a table"),
    el("div", { class: "table-wrap" }, el("table", null,
      el("caption", null, `Per ${BUCKET_S} s bucket, honest devices only`),
      el("thead", null, el("tr", null, el("th", { scope: "col" }, "Time"), el("th", { scope: "col", class: "num" }, "p50"),
        el("th", { scope: "col", class: "num" }, "p95"), el("th", { scope: "col", class: "num" }, "Message rate"),
        el("th", { scope: "col", class: "num" }, "Messages"))), tableBody)));
  const body = el("div", { class: "panel-body" }, legendRow, latSvg, rateTitle, rateSvg, caption, tooltip, table);
  note.textContent = `Last ${WINDOW_MIN} minutes. Device send to ingest receive, only messages with a genuine device envelope.`;

  function series() {
    const cutoff = Date.now() - WINDOW_MIN * 60_000;
    for (const t of buckets.keys()) if (t < cutoff) buckets.delete(t);
    return [...buckets.values()].sort((a, b) => a.t - b.t);
  }

  function visibleRuns(t0, t1) {
    const out = [];
    for (const r of runs) {
      const a = r?.attacks?.[0];
      const start = a?.started_at ? new Date(a.started_at).getTime() : NaN;
      const endRaw = a?.ended_at || a?.planned_end || r?.ended_at;
      const end = endRaw ? new Date(endRaw).getTime() : NaN;
      if (!Number.isFinite(start)) continue;
      const e = Number.isFinite(end) ? end : Date.now();
      if (e < t0 || start > t1) continue;
      out.push({ start: Math.max(start, t0), end: Math.min(e, t1), rate: a.rate_per_s });
    }
    return out;
  }

  function draw() {
    if (!loaded) return;
    const pts = series();
    if (pts.length === 0) {
      replace(container, stateMessage(`No honest-device messages in the last ${WINDOW_MIN} minutes.`));
      return;
    }
    if (!container.contains(body)) replace(container, body);
    for (const b of scaleButtons) b.setAttribute("aria-pressed", String(b.textContent.startsWith(scale === "log" ? "Log" : "Linear")));
    width = Math.max(320, Math.floor(container.clientWidth));
    const t1 = Date.now();
    // Start the axis at the first data point, not at an empty "10 minutes ago".
    const t0 = Math.max(t1 - WINDOW_MIN * 60_000, pts[0].t);
    const span = Math.max(t1 - t0, BUCKET_S * 1000);
    const plotW = width - M.left - M.right;
    const x = (t) => M.left + ((t - t0) / span) * plotW;
    const dataMax = Math.max(...pts.map((p) => Math.max(p.p95_ms ?? 0, p.p50_ms ?? 0)), 1);
    const plotH = H_LAT - M.top - M.bottom;
    let yLat;
    let latTicks;
    if (scale === "log") {
      const hi = Math.max(10, 10 ** Math.ceil(Math.log10(dataMax * 1.2)));
      const [l0, l1] = [Math.log10(LOG_FLOOR_MS), Math.log10(hi)];
      yLat = (v) => M.top + (1 - (Math.log10(Math.max(v, LOG_FLOOR_MS)) - l0) / (l1 - l0)) * plotH;
      latTicks = [];
      for (let v = 1; v <= hi; v *= 10) latTicks.push(v);
    } else {
      const hi = niceMax(dataMax * 1.1);
      yLat = (v) => M.top + (1 - v / hi) * plotH;
      latTicks = linearTicks(hi);
    }
    const rateMax = niceMax(Math.max(...pts.map((p) => p.rate_per_s ?? 0), 0.5) * 1.15);
    const yRate = (v) => 6 + (1 - v / rateMax) * (H_RATE - 6 - M.bottom);
    const flood = visibleRuns(t0, t1);
    const last = pts[pts.length - 1];

    // Legend doubles as the current readout.
    replace(legend,
      el("span", { class: "legend-key" }, lineKey("s-p95"), `p95 ${ms(last.p95_ms)}`),
      el("span", { class: "legend-key" }, lineKey("s-p50"), `p50 ${ms(last.p50_ms)}`),
      flood.length ? el("span", { class: "legend-key" }, el("span", { class: "shape", dataset: { tone: "crit", shape: "square" }, "aria-hidden": "true" }), "Flood run") : null);

    latSvg.setAttribute("viewBox", `0 0 ${width} ${H_LAT}`);
    latSvg.setAttribute("height", H_LAT);
    latSvg.setAttribute("aria-label", `Honest-device latency, ${scale} scale. Latest p95 ${ms(last.p95_ms)}, p50 ${ms(last.p50_ms)}. ${flood.length} flood run${flood.length === 1 ? "" : "s"} in view. Use the arrow keys to read values.`);
    const lat = [];
    let labelRight = -Infinity; // skip a run label that would overlap the previous one
    for (const f of flood.sort((a, b) => a.start - b.start)) {
      lat.push(svg("rect", { class: "flood", x: x(f.start), y: M.top, width: Math.max(1, x(f.end) - x(f.start)), height: plotH }));
      lat.push(svg("line", { class: "flood-edge", x1: x(f.start), x2: x(f.start), y1: M.top, y2: H_LAT - M.bottom }));
      const label = `Flood ${num(f.rate)} msg/s`;
      const labelW = label.length * 6.6;
      const lx = x(f.start) + 5;
      if (x(f.end) - x(f.start) > labelW + 8 && lx > labelRight + 8) {
        lat.push(svg("text", { class: "flood-label", x: lx, y: M.top - 6 }, label));
        labelRight = lx + labelW;
      }
    }
    for (const v of latTicks) {
      lat.push(svg("line", { class: v === 0 ? "baseline" : "grid", x1: M.left, x2: M.left + plotW, y1: yLat(v), y2: yLat(v) }));
      lat.push(svg("text", { class: "tick", x: M.left - 8, y: yLat(v) + 4, "text-anchor": "end" }, `${num(v, v % 1 ? 1 : 0)} ms`));
    }
    if (scale === "log") lat.push(svg("line", { class: "baseline", x1: M.left, x2: M.left + plotW, y1: H_LAT - M.bottom, y2: H_LAT - M.bottom }));
    const step = timeStep(span);
    for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) {
      lat.push(svg("text", { class: "tick", x: x(t), y: H_LAT - 6, "text-anchor": "middle" }, step < 60_000 ? clock(new Date(t)) : shortClock(new Date(t))));
    }
    const bucketMs = BUCKET_S * 1000;
    lat.push(svg("path", { class: "series s-p50", d: pathFor(pts, x, yLat, "p50_ms", bucketMs) }));
    lat.push(svg("path", { class: "series s-p95", d: pathFor(pts, x, yLat, "p95_ms", bucketMs) }));
    const ends = [["p95_ms", "s-p95", "p95"], ["p50_ms", "s-p50", "p50"]].filter(([k]) => isNum(last[k]));
    for (const [k, cls] of ends) lat.push(svg("circle", { class: `end-dot ${cls}`, cx: x(last.t), cy: yLat(last[k]), r: 4 }));
    // Direct end labels only when they do not collide; otherwise the legend carries them.
    if (ends.length === 2 && Math.abs(yLat(last.p95_ms) - yLat(last.p50_ms)) >= 14) {
      for (const [k, , name] of ends) lat.push(svg("text", { class: "end-label", x: x(last.t) + 9, y: yLat(last[k]) + 4 }, `${name} ${ms(last[k])}`));
    }
    const crossLat = svg("line", { class: "crosshair", y1: M.top, y2: H_LAT - M.bottom, visibility: "hidden" });
    lat.push(crossLat);
    const hit = svg("rect", { x: M.left, y: 0, width: plotW, height: H_LAT, fill: "transparent" });
    lat.push(hit);
    latSvg.replaceChildren(...lat);

    rateSvg.setAttribute("viewBox", `0 0 ${width} ${H_RATE}`);
    rateSvg.setAttribute("height", H_RATE);
    const rt = [];
    for (const f of flood) rt.push(svg("rect", { class: "flood", x: x(f.start), y: 6, width: Math.max(1, x(f.end) - x(f.start)), height: H_RATE - 6 - M.bottom }));
    for (const v of linearTicks(rateMax, 2)) {
      rt.push(svg("line", { class: v === 0 ? "baseline" : "grid", x1: M.left, x2: M.left + plotW, y1: yRate(v), y2: yRate(v) }));
      rt.push(svg("text", { class: "tick", x: M.left - 8, y: yRate(v) + 4, "text-anchor": "end" }, `${num(v, v % 1 ? 1 : 0)} msg/s`));
    }
    rt.push(svg("path", { class: "series s-rate", d: pathFor(pts, x, yRate, "rate_per_s", bucketMs) }));
    const crossRate = svg("line", { class: "crosshair", y1: 6, y2: H_RATE - M.bottom, visibility: "hidden" });
    rt.push(crossRate);
    rateSvg.replaceChildren(...rt);

    const counts = pts.map((p) => p.messages).filter(isNum).sort((a, b) => a - b);
    const median = counts.length ? counts[Math.floor(counts.length / 2)] : null;
    caption.textContent = isNum(median)
      ? `Each point is one ${BUCKET_S} s bucket of about ${plural(median, "message", "messages")}, so its p95 is close to that bucket’s slowest message.`
      : "";

    function show(i) {
      if (i < 0 || i >= pts.length) { hide(); return; }
      focusIndex = i;
      const p = pts[i];
      const cx = x(p.t);
      for (const line of [crossLat, crossRate]) { line.setAttribute("x1", cx); line.setAttribute("x2", cx); line.setAttribute("visibility", "visible"); }
      const inFlood = flood.find((f) => p.t >= f.start && p.t <= f.end);
      replace(tooltip,
        el("div", { class: "tt-time" }, `${clock(new Date(p.t))}, ${plural(p.messages, "message", "messages")}`),
        el("div", { class: "tt-row" }, lineKey("s-p95"), "p95", el("strong", null, ms(p.p95_ms))),
        el("div", { class: "tt-row" }, lineKey("s-p50"), "p50", el("strong", null, ms(p.p50_ms))),
        el("div", { class: "tt-row" }, lineKey("s-rate"), "Rate", el("strong", null, rate(p.rate_per_s))),
        inFlood ? el("div", { class: "tt-row" }, `Flood ${num(inFlood.rate)} msg/s`) : null);
      tooltip.hidden = false;
      const tw = tooltip.offsetWidth;
      tooltip.style.left = `${Math.max(0, cx + 12 + tw > width ? cx - 12 - tw : cx + 12)}px`;
      tooltip.style.top = `${legendRow.offsetHeight + 12}px`;
    }
    function hide() {
      focusIndex = -1;
      tooltip.hidden = true;
      for (const line of [crossLat, crossRate]) line.setAttribute("visibility", "hidden");
    }
    function nearest(clientX) {
      const box = latSvg.getBoundingClientRect();
      const px = ((clientX - box.left) / box.width) * width;
      let best = 0;
      for (let i = 1; i < pts.length; i++) if (Math.abs(x(pts[i].t) - px) < Math.abs(x(pts[best].t) - px)) best = i;
      return best;
    }
    hit.addEventListener("pointermove", (e) => show(nearest(e.clientX)));
    hit.addEventListener("pointerleave", hide);
    latSvg.onkeydown = (e) => {
      if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        e.preventDefault();
        const start = focusIndex < 0 ? pts.length - 1 : focusIndex + (e.key === "ArrowRight" ? 1 : -1);
        show(Math.max(0, Math.min(pts.length - 1, start)));
      } else if (e.key === "Escape") hide();
    };
    latSvg.onblur = hide;
    if (focusIndex >= 0) show(Math.min(focusIndex, pts.length - 1));

    tableBody.replaceChildren(...pts.slice().reverse().map((p) => el("tr", null,
      el("td", null, clock(new Date(p.t))), el("td", { class: "num" }, ms(p.p50_ms)),
      el("td", { class: "num" }, ms(p.p95_ms)), el("td", { class: "num" }, rate(p.rate_per_s)),
      el("td", { class: "num" }, num(p.messages)))));
  }

  function merge(data) {
    for (const b of data?.buckets ?? []) {
      const t = new Date(b.t).getTime();
      if (Number.isFinite(t)) buckets.set(t, { t, p50_ms: b.p50_ms, p95_ms: b.p95_ms, rate_per_s: b.rate_per_s, messages: b.messages });
    }
    loaded = true;
    container.closest(".panel")?.removeAttribute("data-stale");
    draw();
  }

  function query() {
    const base = `/telemetry/series?minutes=${WINDOW_MIN}&bucket_s=${BUCKET_S}`;
    // After the first load, fetch only from the newest bucket on (it may still be filling).
    const newest = buckets.size ? Math.max(...buckets.keys()) : null;
    return newest ? `${base}&since=${encodeURIComponent(new Date(newest).toISOString())}` : base;
  }

  function setRuns(list) { runs = Array.isArray(list) ? list : []; draw(); }

  function showError(err) {
    if (!loaded) replace(container, stateMessage(`Could not load latency: ${err.detail || err.message}. Retrying.`, "crit"));
    else container.closest(".panel")?.setAttribute("data-stale", "");
  }

  function reset() { buckets.clear(); loaded = false; replace(container, stateMessage("Loading latency…")); }

  new ResizeObserver(() => { if (loaded && Math.floor(container.clientWidth) !== width) draw(); }).observe(container);
  replace(container, stateMessage("Loading latency…"));
  return { merge, query, setRuns, showError, reset, redraw: draw };
}
