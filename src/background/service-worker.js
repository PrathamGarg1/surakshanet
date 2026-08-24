import { pipeline, env } from '@xenova/transformers';
import { saveEvidence } from '../storage.js';

env.allowLocalModels = true;
env.allowRemoteModels = false;
env.localModelPath = chrome.runtime.getURL('assets/models/');
env.useBrowserCache = true;
env.backends.onnx.wasm.numThreads = 1;
env.backends.onnx.wasm.proxy = false;
env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('assets/');

let classifier = null;
let inferenceQueue = Promise.resolve();
const THRESHOLD = 0.65;
const CACHE_KEY = 'inference_cache';
const CACHE_MAX = 8000;

async function hashText(text) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text.trim().toLowerCase())
  );
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

async function getCache(text) {
  const data = await chrome.storage.session.get(CACHE_KEY);
  const c = data[CACHE_KEY] || { order: [], map: {} };
  return c.map[await hashText(text)] || null;
}

async function setCache(text, verdict) {
  const key = await hashText(text);
  const data = await chrome.storage.session.get(CACHE_KEY);
  const c = data[CACHE_KEY] || { order: [], map: {} };
  if (!c.map[key]) c.order.push(key);
  else c.order = c.order.filter((k) => k !== key).concat(key);
  c.map[key] = verdict;
  while (c.order.length > CACHE_MAX) delete c.map[c.order.shift()];
  await chrome.storage.session.set({ [CACHE_KEY]: c });
}

async function loadModel() {
  if (classifier) return;
  classifier = await pipeline('text-classification', 'custom-macd-model', { top_k: null });
}

function analyze(results) {
  let maxScore = 0;
  for (const r of results) {
    const label = r.label.toLowerCase();
    const abusive =
      ['abusive', 'label_0'].includes(label) && !['non-abusive', 'label_1'].includes(label);
    if (abusive && r.score >= THRESHOLD) maxScore = Math.max(maxScore, r.score);
  }
  const isToxic = maxScore > 0;
  return {
    isToxic,
    maxScore,
    severity: isToxic ? (maxScore > 0.85 ? 'HIGH' : 'MEDIUM') : null,
  };
}

async function classify(text) {
  const hit = await getCache(text);
  if (hit) return hit;
  await loadModel();
  const analysis = analyze(await classifier(text));
  await setCache(text, analysis);
  return analysis;
}

function runQueued(fn) {
  inferenceQueue = inferenceQueue.then(fn, fn);
}

chrome.runtime.onInstalled.addListener(() => loadModel().catch(console.error));
chrome.runtime.onStartup.addListener(() => loadModel().catch(console.error));

chrome.runtime.onMessage.addListener((req, _sender, sendResponse) => {
  if (req.type !== 'ANALYZE_BATCH') return;

  runQueued(async () => {
    try {
      const results = [];
      for (const item of req.items || []) {
        const a = await classify(item.text);
        if (a.isToxic) {
          await saveEvidence({
            text: item.text,
            source: req.source || 'web.whatsapp.com',
            severity: a.severity,
            maxScore: a.maxScore,
            timestamp: Date.now(),
          });
        }
        results.push({
          id: item.id,
          isToxic: a.isToxic,
          severity: a.severity,
          maxScore: a.maxScore,
        });
      }
      sendResponse({ results });
    } catch (e) {
      console.error('[SurakshaNet]', e);
      sendResponse({ results: [], error: e.message });
    }
  });
  return true;
});
