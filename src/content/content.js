import { showBanner } from './banner.js';

const TEXT_MIN = 5;
const TEXT_MAX = 2000;
const SEEN_MAX = 4000;
const BATCH_MS = 300;
const MAX_BATCH = 12;

const MESSAGE_SELECTORS = [
  '.message-in span[data-testid="selectable-text"]',
  '.message-out span[data-testid="selectable-text"]',
  'span[data-testid="selectable-text"]',
];

const seenText = new Set();
const seenOrder = [];
const tracked = new WeakSet();
const pendingQueue = new Map();
let batchTimer = null;
let nextId = 0;

function rememberText(text) {
  if (seenText.has(text)) return false;
  seenText.add(text);
  seenOrder.push(text);
  if (seenOrder.length > SEEN_MAX) seenText.delete(seenOrder.shift());
  return true;
}

function extractText(el) {
  const text = el.innerText?.trim();
  if (!text || text.length < TEXT_MIN || text.length > TEXT_MAX) return null;
  return text;
}

function flushBatch() {
  batchTimer = null;
  if (!chrome?.runtime?.sendMessage || pendingQueue.size === 0) return;

  const entries = Array.from(pendingQueue.entries()).slice(0, MAX_BATCH);
  chrome.runtime.sendMessage(
    {
      type: 'ANALYZE_BATCH',
      source: window.location.hostname,
      items: entries.map(([id, v]) => ({ id, text: v.text })),
    },
    (response) => {
      if (chrome.runtime.lastError || !response?.results) {
        pendingQueue.clear();
        return;
      }
      for (const r of response.results) {
        const item = pendingQueue.get(r.id);
        if (!item) continue;
        pendingQueue.delete(r.id);
        if (r.isToxic) showBanner(item.element, r);
      }
      if (pendingQueue.size > 0) scheduleBatch();
    }
  );
}

function scheduleBatch() {
  if (!batchTimer) batchTimer = setTimeout(flushBatch, BATCH_MS);
}

function queueElement(el) {
  const text = extractText(el);
  if (!text || !rememberText(text)) return;
  if (!chrome?.runtime?.sendMessage) return;

  const id = String(++nextId);
  pendingQueue.set(id, { text, element: el });
  scheduleBatch();
}

const viewportObserver = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) queueElement(entry.target);
    }
  },
  { root: null, rootMargin: '120px 0px', threshold: 0.01 }
);

function trackElement(el) {
  if (tracked.has(el)) return;
  tracked.add(el);
  viewportObserver.observe(el);
}

function findMessageElements(root = document.body) {
  const found = [];
  for (const sel of MESSAGE_SELECTORS) {
    root.querySelectorAll(sel).forEach((el) => found.push(el));
  }
  return found;
}

function attachInSubtree(root) {
  if (!root) return;
  if (root.nodeType === Node.ELEMENT_NODE) {
    for (const sel of MESSAGE_SELECTORS) {
      if (root.matches?.(sel)) trackElement(root);
    }
  }
  findMessageElements(root).forEach(trackElement);
}

function startObservers() {
  const root = document.body || document.documentElement;
  if (!root) return setTimeout(startObservers, 200);

  attachInSubtree(root);

  new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) attachInSubtree(node);
      }
    }
  }).observe(root, { childList: true, subtree: true });
}

startObservers();
