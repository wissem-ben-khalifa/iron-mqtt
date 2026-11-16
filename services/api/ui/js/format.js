// Formatting: one place for number formats and units. Every number shown carries a unit.

const LOCALE = "en-GB";
const timeFmt = new Intl.DateTimeFormat(LOCALE, { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });
const shortTimeFmt = new Intl.DateTimeFormat(LOCALE, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
const numCache = new Map();

function nf(digits) {
  const key = digits;
  if (!numCache.has(key)) {
    numCache.set(key, new Intl.NumberFormat("en-US", { minimumFractionDigits: digits, maximumFractionDigits: digits }));
  }
  return numCache.get(key);
}

export const MISSING = "Not reported";

export function isNum(v) {
  return typeof v === "number" && Number.isFinite(v);
}

export function num(v, digits = 0) {
  return isNum(v) ? nf(digits).format(v) : MISSING;
}

// Milliseconds with precision that suits the magnitude: 0.77 ms, 17.5 ms, 1,960 ms.
export function ms(v) {
  if (!isNum(v)) return MISSING;
  if (v > 0 && v < 0.01) return `${nf(1).format(v * 1000)} µs`;
  const digits = v < 10 ? 2 : v < 100 ? 1 : 0;
  return `${nf(digits).format(v)} ms`;
}

export function rate(v) {
  if (!isNum(v)) return MISSING;
  const digits = v === 0 ? 0 : v < 1 ? 2 : v < 100 ? 1 : 0;
  return `${nf(digits).format(v)} msg/s`;
}

export function seconds(v) {
  if (!isNum(v)) return MISSING;
  return `${nf(v < 10 ? 2 : v < 100 ? 1 : 0).format(v)} s`;
}

export function percent(share) {
  if (!isNum(share)) return MISSING;
  // Never round a probability up to certainty, or down to zero.
  if (share < 1 && share >= 0.9995) return ">99.9%";
  if (share > 0 && share < 0.0005) return "<0.1%";
  return `${nf(1).format(share * 100)}%`;
}

export function ratio(v, digits = 3) {
  return isNum(v) ? nf(digits).format(v) : MISSING;
}

export function parseTime(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function clock(value) {
  const d = value instanceof Date ? value : parseTime(value);
  return d ? timeFmt.format(d) : MISSING;
}

export function shortClock(d) {
  return shortTimeFmt.format(d);
}

// "4 s ago", "3 min ago", "2 h ago"; a full date after a day; flags timestamps from the future.
export function ago(value, now = Date.now()) {
  const d = value instanceof Date ? value : parseTime(value);
  if (!d) return MISSING;
  const raw = Math.round((now - d.getTime()) / 1000);
  if (raw < -5) return "In the future, clock skew";
  const s = Math.max(0, raw);
  if (s < 2) return "just now";
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return localDateTime(d);
}

export function durationBetween(a, b) {
  const da = parseTime(a);
  const db = parseTime(b);
  if (!da || !db) return MISSING;
  return seconds((db - da) / 1000);
}

export function plural(n, one, many) {
  return `${num(n)} ${n === 1 ? one : many}`;
}

// Feature values, formatted with the catalog from GET /features/catalog (name, label, unit).
// Gaps (stored in seconds) are shown in ms below one second; ratios as "30.3 : 1".
export function featureValue(v, unit, name = "") {
  if (!isNum(v)) return MISSING;
  if (unit === null) return `${nf(1).format(v)} : 1`;
  const [one, many] = unit || ["", ""];
  if (one === "s" && name.startsWith("iat_") && Math.abs(v) < 1) return ms(v * 1000);
  if (one === "s") return seconds(v);
  if (one === "B") return `${nf(Number.isInteger(v) ? 0 : 1).format(v)} B`;
  const n = Number.isInteger(v) ? v : Math.round(v * 10) / 10;
  return `${nf(Number.isInteger(n) ? 0 : 1).format(n)} ${n === 1 ? one : many}`.trim();
}

// Local time with its UTC offset, for labelling (the API and pcap file names use UTC).
export function zoneLabel(d = new Date()) {
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const h = String(Math.floor(Math.abs(off) / 60)).padStart(2, "0");
  const m = String(Math.abs(off) % 60).padStart(2, "0");
  return `UTC${sign}${h}:${m}`;
}

export function localDateTime(value) {
  const d = value instanceof Date ? value : parseTime(value);
  if (!d) return MISSING;
  const date = new Intl.DateTimeFormat(LOCALE, { day: "numeric", month: "short", year: "numeric" }).format(d);
  return `${date}, ${clock(d)}`;
}

const DEVICE_TYPES = { env_sensor: "Env sensor", smart_plug: "Smart plug", door_sensor: "Door sensor", camera: "Camera" };
export function humanize(code) {
  if (!code) return MISSING;
  const text = String(code).replace(/_/g, " ").trim();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function deviceType(t) {
  return DEVICE_TYPES[t] || (t ? humanize(t) : MISSING);
}
