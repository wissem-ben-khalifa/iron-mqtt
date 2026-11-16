// Status bar: devices online, detector model, last incident, live connection.

import { replace, status } from "./dom.js";
import { ago, clock, isNum, zoneLabel } from "./format.js";

export function createStatusBar() {
  const $ = (id) => document.getElementById(id);
  const nodes = { devices: $("st-devices"), model: $("st-model"), incident: $("st-incident"), live: $("st-live"), zone: $("st-zone") };
  nodes.zone.textContent = `Local, ${zoneLabel()}`;
  let lastIncidentAt = null;

  return {
    devices({ reporting, total }) {
      if (total === 0) { replace(nodes.devices, status("off", "ring", "None reporting")); return; }
      const tone = reporting === total ? "good" : reporting === 0 ? "crit" : "warn";
      const shape = reporting === total ? "dot" : reporting === 0 ? "square" : "tri";
      replace(nodes.devices, status(tone, shape, `${reporting} of ${total}`));
    },
    detector(s) {
      if (!s?.model_version) { replace(nodes.model, status("warn", "tri", "No windows scored yet")); return; }
      const idle = isNum(s.windows_last_30s) && s.windows_last_30s === 0;
      replace(nodes.model, idle ? status("warn", "tri", `${s.model_version}, idle`) : status("good", "dot", s.model_version));
    },
    lastIncident(value) {
      lastIncidentAt = value || null;
      nodes.incident.textContent = lastIncidentAt ? `${clock(lastIncidentAt)} (${ago(lastIncidentAt)})` : "None yet";
    },
    live(s) {
      const views = {
        connecting: ["warn", "ring-gap", "Connecting"],
        connected: ["good", "dot", "Connected"],
        reconnecting: ["warn", "ring-gap", s.inSeconds ? `Reconnecting in ${s.inSeconds} s` : "Reconnecting"],
        rejected: ["crit", "square", "Token rejected"],
        locked: ["off", "ring", "Locked"],
        fixtures: ["warn", "tri", "Worst-case data"],
      };
      const [tone, shape, word] = views[s.state] || ["off", "ring", "Not connected"];
      replace(nodes.live, status(tone, shape, word));
    },
    unknown(what) {
      const node = nodes[what];
      if (node && node.textContent === "Loading…") replace(node, status("off", "ring", "Unknown, API unreachable"));
    },
    tick() {
      if (lastIncidentAt) nodes.incident.textContent = `${clock(lastIncidentAt)} (${ago(lastIncidentAt)})`;
    },
  };
}
