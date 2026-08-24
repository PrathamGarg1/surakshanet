import { getAllEvidence, verifyChain, exportJSON } from '../storage.js';

const totalEl = document.getElementById('totalIncidents');
const highEl = document.getElementById('highSeverity');
const medEl = document.getElementById('mediumSeverity');
const listEl = document.getElementById('evidenceList');
const emptyEl = document.getElementById('emptyState');
const toast = document.getElementById('toast');

function showToast(msg, err = false) {
  toast.textContent = msg;
  toast.className = err ? 'err' : '';
  toast.style.display = 'block';
  setTimeout(() => { toast.style.display = 'none'; }, 3000);
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

async function render() {
  const rows = await getAllEvidence();
  totalEl.textContent = rows.length;
  highEl.textContent = rows.filter((r) => r.severity === 'HIGH').length;
  medEl.textContent = rows.filter((r) => r.severity === 'MEDIUM').length;

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
      <div class="evidence-meta">WhatsApp · #${e.seq}</div>
      <div class="evidence-text">${(e.textPreview || '').replace(/</g, '&lt;')}</div>
    </div>`
    )
    .join('');
}

document.getElementById('verify').onclick = async () => {
  const r = await verifyChain();
  showToast(
    r.ok ? `Chain OK · ${r.n} records` : `Broken @ #${r.at}: ${r.reason}`,
    !r.ok
  );
};

document.getElementById('export').onclick = async () => {
  const json = await exportJSON();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  a.download = `surakshanet_${Date.now()}.json`;
  a.click();
  showToast('JSON exported');
};

render();
setInterval(render, 3000);
