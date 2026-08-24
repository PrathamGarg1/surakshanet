import { pipeline, env } from '@xenova/transformers';
import { saveEvidence, exportJSON } from '../storage.js';

env.allowLocalModels = true;
env.allowRemoteModels = false;
env.useBrowserCache = false;
env.localModelPath = chrome.runtime.getURL('assets/models/');
env.backends.onnx.wasm.numThreads = 1;
env.backends.onnx.wasm.proxy = false;
env.backends.onnx.wasm.simd = true;
env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('assets/');

let clf = null;
let modelError = null;
let modelLoading = null;
let inferQueue = Promise.resolve();
const THRESHOLD = 0.65;
const CACHE = 'sn_inf';
const CACHE_MAX = 4000;

console.log('[SurakshaNet] service worker started', chrome.runtime.getManifest().version);

async function h(t) {
  const b = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(t.trim().toLowerCase())
  );
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

async function cached(text) {
  const c = (await chrome.storage.session.get(CACHE))[CACHE] || { o: [], m: {} };
  return c.m[await h(text)] || null;
}

async function putCache(text, v) {
  const k = await h(text);
  const c = (await chrome.storage.session.get(CACHE))[CACHE] || { o: [], m: {} };
  if (!c.m[k]) c.o.push(k);
  c.m[k] = v;
  while (c.o.length > CACHE_MAX) delete c.m[c.o.shift()];
  await chrome.storage.session.set({ [CACHE]: c });
}

async function loadModel() {
  if (clf) return clf;
  if (modelLoading) return modelLoading;
  modelLoading = (async () => {
    try {
      console.log('[SurakshaNet] loading model from', env.localModelPath);
      clf = await pipeline('text-classification', 'custom-macd-model', {
        top_k: null,
        quantized: true,
      });
      modelError = null;
      console.log('[SurakshaNet] model ready');
      return clf;
    } catch (e) {
      modelError = e.message || String(e);
      console.error('[SurakshaNet] model load failed:', e);
      throw e;
    } finally {
      modelLoading = null;
    }
  })();
  return modelLoading;
}

function verdict(results) {
  let abusiveScore = 0;
  for (const r of results) {
    const L = String(r.label).toLowerCase();
    const isAbusive =
      L === 'abusive' || L === 'label_0' || L.includes('abusive') || L === '0';
    if (isAbusive) abusiveScore = Math.max(abusiveScore, r.score);
  }
  // Fallback: lower index = abusive in our id2label
  if (!abusiveScore && results.length >= 2) {
    const s0 = results.find((r) => String(r.label).toLowerCase().includes('0'));
    if (s0) abusiveScore = s0.score;
  }
  const isToxic = abusiveScore >= THRESHOLD;
  return {
    isToxic,
    maxScore: isToxic ? abusiveScore : 0,
    severity: isToxic ? (abusiveScore > 0.85 ? 'HIGH' : 'MEDIUM') : null,
  };
}

async function exportOnHigh() {
  const json = await exportJSON();
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  try {
    await chrome.downloads.download({
      url,
      filename: `surakshanet_${Date.now()}.json`,
      saveAs: false,
    });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
}

async function classify(text) {
  const hit = await cached(text);
  if (hit) return hit;
  await loadModel();
  const raw = await clf(text);
  const v = verdict(Array.isArray(raw) ? raw : [raw]);
  await putCache(text, v);
  return v;
}

function status() {
  return {
    ok: true,
    modelReady: Boolean(clf),
    modelLoading: Boolean(modelLoading),
    modelError,
  };
}

function runInfer(fn) {
  const p = inferQueue.then(fn);
  inferQueue = p.catch(() => {});
  return p;
}

chrome.runtime.onInstalled.addListener(() => loadModel().catch(console.error));
chrome.runtime.onStartup.addListener(() => loadModel().catch(console.error));
loadModel().catch(console.error);

chrome.runtime.onMessage.addListener((req, _s, send) => {
  if (req.type === 'PING') {
    send(status());
    return;
  }

  if (req.type === 'CLASSIFY_ONE') {
    runInfer(() => classify(req.text || ''))
      .then((r) => send({ ok: true, ...r }))
      .catch((e) => send({ ok: false, error: e.message }));
    return true;
  }

  if (req.type !== 'ANALYZE_BATCH') return;

  runInfer(async () => {
    const results = [];
    let sawHigh = false;
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
        if (a.severity === 'HIGH') sawHigh = true;
      }
      results.push({ id: item.id, ...a });
    }
    if (sawHigh) await exportOnHigh();
    return { results };
  })
    .then((out) => send(out))
    .catch((e) => {
      console.error('[SurakshaNet] batch error:', e);
      send({ results: [], error: e.message });
    });

  return true;
});

self.addEventListener('error', (e) => console.error('[SurakshaNet] SW error:', e.error || e.message));
self.addEventListener('unhandledrejection', (e) =>
  console.error('[SurakshaNet] SW unhandled:', e.reason)
);
