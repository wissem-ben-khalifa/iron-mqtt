// The single data boundary of the console. Every panel reads through request(); the dev-only
// worst-case module (served only when DEV_UI=1) swaps the source here, never in a component.

const TOKEN_KEY = "iron-mqtt.api-token";
let memoryToken = null; // fallback if sessionStorage is unavailable (private mode, blocked storage)

export const token = {
  get() {
    try { return sessionStorage.getItem(TOKEN_KEY) ?? memoryToken; } catch { return memoryToken; }
  },
  set(value) {
    memoryToken = value;
    try { sessionStorage.setItem(TOKEN_KEY, value); } catch { /* memory only */ }
  },
  clear() {
    memoryToken = null;
    try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* nothing stored */ }
  },
};

export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.status = status; // 0 = unreachable
    this.detail = detail;
  }
}

let source = null;
export function setDataSource(fn) { source = fn; }
export function usingFixtures() { return source !== null; }

export async function request(method, path, body) {
  return source ? source(method, path, body) : directRequest(method, path, body);
}

// Always the network, even when a dev fixture source is installed (fixtures pass some calls through).
export async function directRequest(method, path, body) {
  const headers = { Accept: "application/json" };
  const t = token.get();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let res;
  try {
    res = await fetch(path, { method, headers, cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "The API is unreachable.");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") detail = data.detail;
    } catch { /* not JSON */ }
    throw new ApiError(res.status, detail);
  }
  return res.status === 204 ? null : res.json();
}

export const get = (path) => request("GET", path);
export const post = (path, body = {}) => request("POST", path, body);
