import { pipeline, env } from '@xenova/transformers';
import { saveEvidence, exportJSON } from '../storage.js';

env.allowLocalModels = true;
env.allowRemoteModels = false;
env.localModelPath = chrome.runtime.getURL('assets/models/');
env.backends.onnx.wasm.numThreads = 1;
env.backends.onnx.wasm.wasmPaths = chrome.runtime.getURL('assets/');

let clf = null;
let queue = Promise.resolve();
const THRESHOLD = 0.65;
const CACHE = 'sn_inf';
const CACHE_MAX = 4000;

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

async function load() {
  if (!clf) clf = await pipeline('text-classification', 'custom-macd-model', { top_k: null });
}

function verdict(results) {
  let max = 0;
  for (const r of results) {
    const L = r.label.toLowerCase();
    if ((L === 'abusive' || L === 'label_0') && r.score >= THRESHOLD) max = Math.max(max, r.score);
  }
  const isToxic = max > 0;
  return {
    isToxic,
    maxScore: max,
    severity: isToxic ? (max > 0.85 ? 'HIGH' : 'MEDIUM') : null,
  };
}

async function exportOnHigh() {
  const json = await exportJSON();
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
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
  await load();
  const v = verdict(await clf(text));
  await putCache(text, v);
  return v;
}

chrome.runtime.onMessage.addListener((req, _s, send) => {
  if (req.type !== 'ANALYZE_BATCH') return;
  queue = queue.then(async () => {
    try {
      const results = [];
      let sawHigh = false;
      for (const item of req.items || []) {
        const a = await classify(item.text);
        if (a.isToxic) {
          await saveEvidence({
            text: item.text,
            source: req.source,
            severity: a.severity,
            maxScore: a.maxScore,
            timestamp: Date.now(),
          });
          if (a.severity === 'HIGH') sawHigh = true;
        }
        results.push({ id: item.id, ...a });
      }
      if (sawHigh) await exportOnHigh();
      send({ results });
    } catch (e) {
      send({ results: [], error: e.message });
    }
  });
  return true;
});
