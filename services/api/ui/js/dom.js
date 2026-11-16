// DOM helpers. Every piece of API data enters the page through createTextNode (via el's
// children) or textContent, never innerHTML, so data is always rendered as text.

const SVG_NS = "http://www.w3.org/2000/svg";

function apply(node, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "style") throw new Error("inline style attributes are blocked by the CSP; use a class");
    if (key === "class") node.setAttribute("class", value);
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  apply(node, attrs);
  append(node, children);
  return node;
}

export function svg(tag, attrs, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  apply(node, attrs);
  append(node, children);
  return node;
}

export function replace(container, ...children) {
  container.replaceChildren();
  append(container, children);
}

// A status is always a shape plus a word, never colour alone.
export function status(tone, shape, word) {
  return el("span", { class: "det" },
    el("span", { class: "shape", dataset: { tone, shape }, "aria-hidden": "true" }),
    el("span", { class: "status-word", dataset: { tone } }, word));
}

export function stateMessage(text, tone) {
  return el("p", { class: "state-msg", dataset: tone ? { tone } : null }, text);
}
