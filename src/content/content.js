/**
 * WhatsApp Web — scan visible chat messages and classify via service worker.
 */
import { showBanner } from './banner.js';

const TEXT_MIN = 3;
const TEXT_MAX = 2000;
const SEEN_MAX = 5000;
const BATCH_MS = 250;
const MAX_BATCH = 8;
const RESCAN_MS = 2000;

// WhatsApp Web message text nodes (Devanagari + English)
const SELECTORS = [
  '#main span[data-testid="selectable-text"]',
  '#main span.selectable-text',
  'span[data-testid="selectable-text"]',
  '.message-in span[data-testid="selectable-text"]',
  '.message-out span[data-testid="selectable-text"]',
];

const seen = new Set();
const seenOrder = [];
const tracked = new WeakSet();
const pending = new Map();
let batchTimer = null;
let nextId = 0;
let scanCount = 0;

function remember(text) {
  const key = text.trim();
  if (!key || seen.has(key)) return false;
  seen.add(key);
  seenOrder.push(key);
  if (seenOrder.length > SEEN_MAX) seen.delete(seenOrder.shift());
  return true;
}

function extractText(el) {
  const text = (el.innerText || el.textContent || '').trim();
  if (!text || text.length < TEXT_MIN || text.length > TEXT_MAX) return null;
  return text;
}

function flush() {
  batchTimer = null;
  if (!chrome?.runtime?.id || pending.size === 0) return;

  const entries = [...pending.entries()].slice(0, MAX_BATCH);
  const ids = new Set(entries.map(([id]) => id));

  chrome.runtime.sendMessage(
    {
      type: 'ANALYZE_BATCH',
      source: 'web.whatsapp.com',
      items: entries.map(([id, v]) => ({ id, text: v.text })),
    },
    (res) => {
      if (chrome.runtime.lastError) {
        console.warn('[SurakshaNet]', chrome.runtime.lastError.message);
        for (const [id] of entries) pending.delete(id);
        schedule();
        return;
      }
      if (res?.error) console.warn('[SurakshaNet] classify:', res.error);
      if (!res?.results?.length) {
        for (const [id] of entries) pending.delete(id);
        schedule();
        return;
      }
      for (const r of res.results) {
        const item = pending.get(r.id);
        if (!item) continue;
        pending.delete(r.id);
        scanCount++;
        if (r.isToxic) showBanner(item.el, r);
      }
      schedule();
    }
  );
}

function schedule() {
  if (batchTimer || pending.size === 0) return;
  batchTimer = setTimeout(flush, BATCH_MS);
}

function queue(el) {
  const text = extractText(el);
  if (!text || !remember(text)) return;
  pending.set(String(++nextId), { text, el });
  schedule();
}

function isVisible(el) {
  const r = el.getBoundingClientRect();
  if (r.width === 0 && r.height === 0) return false;
  const vh = window.innerHeight || document.documentElement.clientHeight;
  return r.bottom > -80 && r.top < vh + 80;
}

const viewportIo = new IntersectionObserver(
  (entries) => {
    for (const e of entries) if (e.isIntersecting) queue(e.target);
  },
  { root: null, rootMargin: '200px 0px', threshold: 0 }
);

function track(el) {
  if (!el || tracked.has(el)) return;
  tracked.add(el);
  viewportIo.observe(el);
  if (isVisible(el)) queue(el);
}

function findMessages(root = document.body) {
  const out = [];
  for (const sel of SELECTORS) {
    try {
      root.querySelectorAll(sel).forEach((el) => out.push(el));
    } catch (_) {}
  }
  return out;
}

function attach(root) {
  if (!root?.nodeType) return;
  if (root.nodeType === Node.ELEMENT_NODE) {
    for (const sel of SELECTORS) {
      if (root.matches?.(sel)) track(root);
    }
  }
  findMessages(root).forEach(track);
}

function scanVisibleNow() {
  findMessages(document.body).filter(isVisible).forEach(queue);
}

function ensureBadge() {
  if (document.getElementById('sn-wa-badge')) return;
  const b = document.createElement('div');
  b.id = 'sn-wa-badge';
  b.textContent = '🛡 SurakshaNet · scanning WhatsApp';
  b.style.cssText =
    'position:fixed;bottom:16px;right:16px;z-index:99999;padding:8px 12px;' +
    'background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;font:11px/1.3 system-ui;' +
    'border-radius:20px;box-shadow:0 4px 12px rgba(0,0,0,.25);pointer-events:none;opacity:.92';
  document.body.appendChild(b);
}

function start() {
  const tryStart = () => {
    const root = document.body;
    if (!root) return setTimeout(tryStart, 300);
    ensureBadge();
    attach(root);
    scanVisibleNow();

    new MutationObserver((mutations) => {
      for (const m of mutations) {
        for (const n of m.addedNodes) {
          if (n.nodeType === Node.ELEMENT_NODE) attach(n);
        }
      }
    }).observe(root, { childList: true, subtree: true });

    setInterval(scanVisibleNow, RESCAN_MS);

    chrome.runtime.sendMessage({ type: 'PING' }, (r) => {
      if (chrome.runtime.lastError) {
        console.warn('[SurakshaNet] SW:', chrome.runtime.lastError.message);
        return;
      }
      console.log('[SurakshaNet] WhatsApp scanner active', r);
    });
  };
  tryStart();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
