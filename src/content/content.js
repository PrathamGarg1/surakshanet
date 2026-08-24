/**
 * Viewport-only scan.
 * MutationObserver = attach IntersectionObserver to NEW message nodes only.
 * Classify only when a message enters the viewport (not every DOM twitch).
 */
import { showBanner } from './banner.js';

const SELECTORS = [
  '.message-in span[data-testid="selectable-text"]',
  '.message-out span[data-testid="selectable-text"]',
  '[data-testid="tweetText"]',
  'div[role="row"] div[dir="auto"]',
];

const seen = new Set();
const seenOrder = [];
const SEEN_MAX = 4000;
const tracked = new WeakSet();
const pending = new Map();
let timer = null;
let id = 0;

function remember(text) {
  if (seen.has(text)) return false;
  seen.add(text);
  seenOrder.push(text);
  if (seenOrder.length > SEEN_MAX) seen.delete(seenOrder.shift());
  return true;
}

function flush() {
  timer = null;
  if (!chrome?.runtime?.sendMessage || pending.size === 0) return;
  const batch = [...pending.entries()].slice(0, 12);
  chrome.runtime.sendMessage(
    {
      type: 'ANALYZE_BATCH',
      source: location.hostname,
      items: batch.map(([k, v]) => ({ id: k, text: v.text })),
    },
    (res) => {
      if (chrome.runtime.lastError || !res?.results) {
        pending.clear();
        return;
      }
      for (const r of res.results) {
        const item = pending.get(r.id);
        if (!item) continue;
        pending.delete(r.id);
        if (r.isToxic) showBanner(item.el, r);
      }
      if (pending.size) schedule();
    }
  );
}

function schedule() {
  if (!timer) timer = setTimeout(flush, 300);
}

function queue(el) {
  const text = el.innerText?.trim();
  if (!text || text.length < 5 || text.length > 2000 || !remember(text)) return;
  pending.set(String(++id), { text, el });
  schedule();
}

const io = new IntersectionObserver(
  (entries) => {
    for (const e of entries) if (e.isIntersecting) queue(e.target);
  },
  { rootMargin: '120px 0px', threshold: 0.01 }
);

function track(el) {
  if (tracked.has(el)) return;
  tracked.add(el);
  io.observe(el);
}

function attach(root) {
  if (!root || root.nodeType !== 1) return;
  for (const sel of SELECTORS) {
    if (root.matches?.(sel)) track(root);
    root.querySelectorAll?.(sel)?.forEach(track);
  }
}

function start() {
  const root = document.body;
  if (!root) return setTimeout(start, 200);
  attach(root);
  new MutationObserver((ms) => {
    for (const m of ms)
      for (const n of m.addedNodes) if (n.nodeType === 1) attach(n);
  }).observe(root, { childList: true, subtree: true });
}

start();
