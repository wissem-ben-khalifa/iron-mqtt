// Live incident stream. Authenticates with its first message: the token never goes in the URL,
// so it never reaches the server's access log. Reconnects with capped exponential backoff.

import { token } from "./api.js";

export function connectLive({ onIncident, onState }) {
  let ws = null;
  let attempt = 0;
  let timer = null;
  let stopped = false;

  function schedule() {
    attempt += 1;
    const delay = Math.min(15, 2 ** Math.min(attempt, 4));
    onState({ state: "reconnecting", inSeconds: delay, attempt });
    timer = setTimeout(open, delay * 1000);
  }

  function open() {
    if (stopped) return;
    onState({ state: attempt ? "reconnecting" : "connecting", attempt });
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    try {
      ws = new WebSocket(`${scheme}://${location.host}/ws/incidents`);
    } catch {
      schedule();
      return;
    }
    ws.addEventListener("open", () => ws.send(JSON.stringify({ type: "auth", token: token.get() })));
    ws.addEventListener("message", (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.type === "ready") {
        attempt = 0;
        onState({ state: "connected" });
      } else if (msg.type === "incident" && msg.incident) {
        onIncident(msg.incident, msg.op);
      }
    });
    ws.addEventListener("close", (event) => {
      if (stopped) return;
      if (event.code === 1008) { onState({ state: "rejected" }); return; }
      schedule();
    });
  }

  open();
  return {
    close() {
      stopped = true;
      clearTimeout(timer);
      if (ws && ws.readyState <= 1) ws.close();
    },
  };
}
