/**
 * Evidence store — space + integrity.
 *
 * Space: max 100 rows, 30-day TTL, 280-char preview, SHA-256 of full text only.
 * Integrity: append-only hash chain (prevHash → chainHash). No delete API.
 * Limit: user can still wipe chrome.storage via DevTools — export JSON for custody.
 */
const KEY = 'sn_evidence';
const META = 'sn_chain';
const MAX = 100;
const TTL = 30 * 24 * 60 * 60 * 1000;
const PREVIEW = 280;
const GENESIS = '0'.repeat(64);

async function sha(s) {
  const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function chainHash(r) {
  return sha(
    JSON.stringify({
      prevHash: r.prevHash,
      seq: r.seq,
      textHash: r.textHash,
      timestampMs: r.timestampMs,
      maxScore: r.maxScore,
      source: r.source,
    })
  );
}

function prune(list) {
  const now = Date.now();
  return list
    .filter((e) => !e.timestampMs || now - e.timestampMs <= TTL)
    .sort((a, b) => (b.seq || 0) - (a.seq || 0))
    .slice(0, MAX);
}

export async function saveEvidence({ text, source, severity, maxScore, timestamp }) {
  const textHash = await sha(text);
  const data = await chrome.storage.local.get([KEY, META]);
  const list = data[KEY] || [];
  const meta = data[META] || { headHash: GENESIS, seq: 0 };
  if (list.some((e) => e.textHash === textHash)) return;

  const seq = meta.seq + 1;
  const row = {
    seq,
    textHash,
    textPreview: text.slice(0, PREVIEW),
    timestamp: new Date(timestamp || Date.now()).toISOString(),
    timestampMs: timestamp || Date.now(),
    source,
    severity,
    maxScore,
    prevHash: meta.headHash,
  };
  row.chainHash = await chainHash(row);
  list.unshift(row);
  const kept = prune(list);
  meta.headHash = row.chainHash;
  meta.seq = seq;
  await chrome.storage.local.set({ [KEY]: kept, [META]: meta });
}

export async function getAllEvidence() {
  return (await chrome.storage.local.get(KEY))[KEY] || [];
}

export async function verifyChain() {
  const list = [...(await getAllEvidence())].sort((a, b) => a.seq - b.seq);
  let prev = GENESIS;
  for (const r of list) {
    if (r.prevHash !== prev) return { ok: false, at: r.seq, reason: 'broken link' };
    if ((await chainHash(r)) !== r.chainHash)
      return { ok: false, at: r.seq, reason: 'tamper' };
    prev = r.chainHash;
  }
  return { ok: true, n: list.length, head: prev.slice(0, 12) };
}

export async function exportJSON() {
  const evidence = await getAllEvidence();
  const chain = await verifyChain();
  return JSON.stringify({ chainVerified: chain.ok, evidence }, null, 2);
}
