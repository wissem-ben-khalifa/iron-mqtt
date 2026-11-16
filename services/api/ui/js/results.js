// Detector comparison: every number comes from GET /results/summary (committed results data).

import { el, replace, stateMessage } from "./dom.js";
import { MISSING, isNum, localDateTime, num, percent, ratio, seconds, zoneLabel } from "./format.js";

// "m0002 (robust-all)" -> "robust-all"; "window: system-only" -> "system-only". The id column
// already carries the version, so the name is not repeated.
function variant(name) {
  const inner = /^m\d{4} \((.*)\)$/.exec(name || "");
  return (inner ? inner[1] : name || "").replace(/^window: /, "");
}

function perHour(v) {
  return isNum(v) ? `${num(v, 1)} per h` : MISSING;
}

function metricCells(r) {
  return [
    el("td", { class: "num" }, ratio(r.precision)),
    el("td", { class: "num" }, ratio(r.recall)),
    el("td", { class: "num" }, ratio(r.f1)),
    el("td", { class: "num" }, perHour(r.fp_per_hour)),
  ];
}

function headRow(...cols) {
  return el("thead", null, el("tr", null, cols.map(([label, numeric]) =>
    el("th", { scope: "col", class: numeric ? "num" : null }, label))));
}

export function renderResults(container, note, summary) {
  const run = summary?.test_run || {};
  const det = summary?.detectors?.rows;
  const rob = summary?.robust_models?.rows;
  if (!Array.isArray(det) || !Array.isArray(rob)) {
    replace(container, stateMessage("The results summary is missing its tables. Run scripts/export_results.py and rebuild."));
    return;
  }
  note.textContent = `Test run ${run.name || MISSING}: ${num(run.windows)} windows of 5 s, ${num(run.attack_windows)} during a ${num(run.attack_rate_per_s)} msg/s flood. Trained on ${run.trained_on || MISSING}.`;

  const detTable = el("table", null,
    el("caption", null, `${summary.detectors.title}. Source: ${summary.detectors.command}`),
    headRow(["Detector"], ["Precision", 1], ["Recall", 1], ["F1", 1], ["False alarms per hour", 1]),
    el("tbody", null, det.map((r) => el("tr", null, el("th", { scope: "row" }, r.name || MISSING), metricCells(r)))));

  const robTable = el("table", null,
    el("caption", null, `${summary.robust_models.title}. Source: ${summary.robust_models.command}`),
    el("thead", null,
      el("tr", null,
        el("th", { scope: "col", rowspan: 2 }, "Model"), el("th", { scope: "col", rowspan: 2 }, "Decides"),
        el("th", { scope: "col", rowspan: 2, class: "num" }, "F1"), el("th", { scope: "col", rowspan: 2, class: "num" }, "First alert"),
        el("th", { scope: "colgroup", colspan: 3, class: "group" }, "Share of decision weight on features set by")),
      el("tr", null,
        el("th", { scope: "col", class: "num" }, "Device"), el("th", { scope: "col", class: "num" }, "Partial"),
        el("th", { scope: "col", class: "num" }, "System"))),
    el("tbody", null, rob.map((r) => el("tr", null,
      el("th", { scope: "row" }, el("span", { translate: "no" }, r.id || MISSING), el("span", { class: "sub" }, variant(r.name))),
      el("td", null, r.granularity === "window" ? "Attack in progress" : "Which source"),
      el("td", { class: "num" }, ratio(r.f1)),
      el("td", { class: "num" }, isNum(r.first_alert_s) ? `${seconds(r.first_alert_s)} after start` : "Never"),
      el("td", { class: "num" }, percent(r.weight_share?.YES)),
      el("td", { class: "num" }, percent(r.weight_share?.PARTIAL)),
      el("td", { class: "num" }, percent(r.weight_share?.SYSTEM))))));

  const classes = summary.robust_models.weight_classes || {};
  replace(container, el("div", { class: "panel-body" },
    el("div", { class: "table-wrap" }, detTable),
    el("div", { class: "table-gap" }),
    el("div", { class: "table-wrap" }, robTable),
    el("dl", { class: "results-legend" },
      el("div", null, el("dt", null, "Device"), el("dd", null, classes.YES || MISSING)),
      el("div", null, el("dt", null, "Partial"), el("dd", null, classes.PARTIAL || MISSING)),
      el("div", null, el("dt", null, "System"), el("dd", null, classes.SYSTEM || MISSING))),
    el("p", { class: "results-legend" },
      `Exported ${localDateTime(summary.generated_at)} (${zoneLabel(new Date(summary.generated_at))}). First alert is offline: end of the first flagged window after the flood started. Details in ${summary.reference || "docs/RESULTS.md"}.`)));
}

export function resultsError(container, err) {
  replace(container, stateMessage(`Could not load the results summary: ${err.detail || err.message}.`, "crit"));
}
