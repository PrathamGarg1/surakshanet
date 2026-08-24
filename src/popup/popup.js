import { getAllEvidence, verifyChain, exportJSON } from '../storage.js';

const dot = document.getElementById('dot');
const statusText = document.getElementById('statusText');
const toast = document.getElementById('toast');
const listEl = document.getElementById('evidenceList');
const emptyEl = document.getElementById('emptyState');
const totalEl = document.getElementById('totalIncidents');
const highEl = document.getElementById('highSeverity');
const medEl = document.getElementById('mediumSeverity');

function showToast(msg, err = false) {
  toast.textContent = msg;
  toast.className = err ? 'err' : '';
  toast.style.display = 'block';
  setTimeout(() => { toast.style.display = 'none'; }, 3500);
}

function setStatus({ modelReady, modelLoading, modelError }) {
  dot.className = 'dot';
  if (modelError) {
    dot.classList.add('err');
    statusText.textContent = `Model error — reload extension · ${modelError}`;
    return;
  }
  if (modelLoading) {
    dot.classList.add('load');
    statusText.textContent = 'Loading model (~118 MB)…';
    return;
  }
  if (modelReady) {
    dot.classList.add('ok');
    statusText.textContent = 'Active on WhatsApp Web';
    return;
  }
  dot.classList.add('load');
  statusText.textContent = 'Starting…';
}

function fmtTime(iso) {
  try {
    return new Date(iso).toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      dateStyle: 'short',
      timeStyle: 'short',
    });
  } catch {
    return iso || '';
  }
}

async function ping() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'PING' }, (r) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
      else resolve(r || { ok: false });
    });
  });
}

async function render() {
  const rows = await getAllEvidence();
  const high = rows.filter((r) => r.severity === 'HIGH').length;
  const med = rows.filter((r) => r.severity === 'MEDIUM').length;
  totalEl.textContent = rows.length;
  highEl.textContent = high;
  medEl.textContent = med;

  if (!rows.length) {
    listEl.innerHTML = '';
    emptyEl.style.display = 'block';
    return;
  }
  emptyEl.style.display = 'none';
  listEl.innerHTML = rows
    .map(
      (e) => `<div class="evidence-item">
      <div class="evidence-header">
        <span class="evidence-meta">${fmtTime(e.timestamp)} · ${(e.maxScore * 100).toFixed(0)}%</span>
        <span class="severity-badge ${e.severity || 'MEDIUM'}">${e.severity || 'MEDIUM'}</span>
      </div>
      <div class="evidence-meta">WhatsApp · record #${e.seq}</div>
      <div class="evidence-text">${(e.textPreview || '').replace(/</g, '&lt;')}</div>
    </div>`
    )
    .join('');
}

async function refreshStatus() {
  const s = await ping();
  if (s.error) {
    dot.className = 'dot err';
    statusText.textContent = 'Offline — load unpacked from dist/ folder';
    return;
  }
  setStatus(s);
}

document.getElementById('verify').onclick = async () => {
  const r = await verifyChain();
  showToast(
    r.ok ? `Chain OK · ${r.n} records · head ${r.head}` : `Broken @ #${r.at}: ${r.reason}`,
    !r.ok
  );
};

document.getElementById('export').onclick = async () => {
  const json = await exportJSON();
  const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  try {
    await chrome.downloads.download({
      url,
      filename: `surakshanet_whatsapp_${Date.now()}.json`,
      saveAs: true,
    });
    showToast('Export started');
  } catch {
    const a = document.createElement('a');
    a.href = url;
    a.download = `surakshanet_whatsapp_${Date.now()}.json`;
    a.click();
    showToast('Downloaded');
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  }
};

render();
refreshStatus();
setInterval(refreshStatus, 2500);
setInterval(render, 4000);
