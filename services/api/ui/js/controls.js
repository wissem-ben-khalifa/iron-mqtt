// Lab controls: pause/resume the fleet, and the fixed flood scenario (confirm, run id, progress).

import { get, post } from "./api.js";
import { el, replace, stateMessage, status } from "./dom.js";
import { clock, num, rate, seconds } from "./format.js";

export function createControls(container, confirmDialog, { onRunChange }) {
  let config = null;
  let poller = null;
  let running = null; // { run_id, started }

  const fleetState = el("p", { class: "control-status" }, "Waiting for the fleet’s state…");
  const fleetStatus = el("p", { class: "control-status", role: "status" });
  let fleetSummary = null;
  const floodStatus = el("div", { class: "control-status", role: "status" });
  const pauseBtn = el("button", { type: "button", class: "btn" }, "Pause fleet");
  const resumeBtn = el("button", { type: "button", class: "btn" }, "Resume fleet");
  const runBtn = el("button", { type: "button", class: "btn btn-primary" }, "Run flood scenario");
  const stopBtn = el("button", { type: "button", class: "btn", disabled: true }, "Stop flood");
  const durationSel = el("select", { id: "flood-duration" });
  const ratesBox = el("div", { class: "control-row", role: "radiogroup", "aria-labelledby": "rate-label" });

  // The buttons follow the state the devices report in their heartbeats, not the last click.
  function setFleet(summary) {
    fleetSummary = summary;
    const { total, paused, reporting } = summary;
    if (!total) {
      fleetState.textContent = "No devices are reporting.";
    } else if (paused === 0) {
      fleetState.textContent = `Running: none of the ${reporting} reporting devices is paused.`;
    } else if (paused === reporting) {
      fleetState.textContent = `Paused: all ${reporting} reporting devices are paused.`;
    } else {
      fleetState.textContent = `Partly paused: ${paused} of ${reporting} reporting devices are paused.`;
    }
    pauseBtn.disabled = !total || paused === reporting;
    resumeBtn.disabled = !total || paused === 0;
  }

  async function fleet(cmd, word) {
    pauseBtn.disabled = resumeBtn.disabled = true;
    try {
      const r = await post("/fleet/commands", { cmd });
      fleetStatus.textContent = `${word} sent at ${clock(r.sent_at)}. The state above updates when the devices confirm.`;
    } catch (err) {
      fleetStatus.textContent = `${word} failed: ${err.detail || err.message}.`;
      if (fleetSummary) setFleet(fleetSummary);
    }
  }
  pauseBtn.addEventListener("click", () => fleet("pause", "Pause"));
  resumeBtn.addEventListener("click", () => fleet("resume", "Resume"));

  function selected() {
    const r = Number(ratesBox.querySelector("input:checked")?.value);
    const d = Number(durationSel.value);
    const ok = config.rates_per_s.includes(r) && config.durations_s.includes(d);
    return ok ? { rate_per_s: r, duration_s: d, qos: config.qos } : null;
  }

  function showFloodState(view) {
    replace(floodStatus, view);
  }

  async function poll() {
    try {
      const s = await get("/attacks/status");
      if (s.state === "running") {
        showFloodState(el("span", null, status("warn", "ring-gap", "Running"), " ",
          el("strong", { translate: "no" }, running.run_id), `, started ${clock(running.started)}. ${num(s.sent)} messages sent so far.`));
        return;
      }
      clearInterval(poller); poller = null;
      // Natural end: record the real stop time and count on the run (ground truth).
      const final = s.state === "done" ? await post("/attacks/stop") : s;
      finish(final);
    } catch (err) {
      showFloodState(`Could not read the flood status: ${err.detail || err.message}. Retrying.`);
    }
  }

  function finish(final) {
    const r = running;
    running = null;
    stopBtn.disabled = true;
    runBtn.disabled = false;
    showFloodState(el("span", null, status("good", "dot", "Finished"), " ",
      el("strong", { translate: "no" }, r?.run_id || "Run"), `: ${num(final?.sent)} messages, ${rate(final?.actual_rate_per_s)} over ${seconds(final?.gen_seconds)}.`));
    onRunChange();
  }

  async function launch(choice) {
    runBtn.disabled = true;
    try {
      const r = await post("/attacks/flood", choice);
      running = { run_id: r.run_id, started: r?.attack?.started_at };
      stopBtn.disabled = false;
      showFloodState(el("span", null, status("warn", "ring-gap", "Running"), " ", el("strong", { translate: "no" }, r.run_id), `, started ${clock(running.started)}.`));
      onRunChange();
      poller = setInterval(poll, 2000);
    } catch (err) {
      runBtn.disabled = false;
      const why = err.status === 409 ? "A flood is already running." : err.status === 502 ? "The attacker agent is unreachable." : `${err.detail || err.message}.`;
      showFloodState(el("span", null, status("crit", "square", "Not started"), ` ${why}`));
    }
  }

  stopBtn.addEventListener("click", async () => {
    stopBtn.disabled = true;
    clearInterval(poller); poller = null;
    try { finish(await post("/attacks/stop")); }
    catch (err) { stopBtn.disabled = false; showFloodState(`Stop failed: ${err.detail || err.message}.`); }
  });

  runBtn.addEventListener("click", () => {
    const choice = selected();
    if (!choice) return;
    const cancel = el("button", { type: "button", class: "btn", value: "cancel" }, "Cancel");
    const go = el("button", { type: "button", class: "btn btn-danger" }, "Run flood");
    replace(confirmDialog,
      el("div", { class: "dialog-head" }, el("h2", { id: "confirm-title" }, "Run the flood scenario?")),
      el("div", { class: "dialog-body" },
        el("p", null, `This sends ${num(choice.rate_per_s)} messages per second for ${num(choice.duration_s)} s from the attacker container, using a compromised device’s valid certificate, against this range’s broker.`),
        el("p", null, "Honest devices will slow down and the detector should raise an incident.")),
      el("div", { class: "dialog-actions" }, cancel, go));
    cancel.addEventListener("click", () => confirmDialog.close());
    go.addEventListener("click", () => { confirmDialog.close(); launch(choice); });
    confirmDialog.showModal();
    cancel.focus(); // the safe choice has focus
  });

  function render(cfg) {
    config = cfg;
    ratesBox.replaceChildren(...cfg.rates_per_s.map((r, i) => el("label", { class: "radio" },
      el("input", { type: "radio", name: "flood-rate", value: r, checked: i === 1 || null }), rate(r))));
    durationSel.replaceChildren(...cfg.durations_s.map((d, i) => el("option", { value: d, selected: i === 1 || null }, `${num(d)} s`)));
    replace(container, el("div", { class: "panel-body" },
      el("fieldset", { class: "control-group" }, el("legend", null, "Fleet"),
        fleetState, el("div", { class: "control-row" }, pauseBtn, resumeBtn), fleetStatus),
      el("fieldset", { class: "control-group" }, el("legend", null, "Flood scenario"),
        el("p", { id: "rate-label", class: "panel-note" }, "Rate"), ratesBox,
        el("div", { class: "control-row" }, el("label", { for: "flood-duration" }, "Duration"), durationSel, runBtn, stopBtn),
        floodStatus)));
  }

  return {
    render,
    setFleet,
    showError(err) { replace(container, stateMessage(`Could not load the lab controls: ${err.detail || err.message}.`, "crit")); },
  };
}
