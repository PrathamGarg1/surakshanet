import { getAllEvidence, verifyChain, exportJSON } from '../storage.js';

async function render() {
  const list = document.getElementById('list');
  const rows = await getAllEvidence();
  if (!rows.length) {
    list.innerHTML = '<div id="empty">No incidents yet</div>';
    return;
  }
  list.innerHTML = rows
    .map(
      (e) => `<div class="row">
      <div class="meta">${e.severity || '?'} · ${(e.maxScore * 100).toFixed(0)}% · ${e.source} · #${e.seq}</div>
      <div class="txt">${(e.textPreview || '').replace(/</g, '&lt;')}</div>
    </div>`
    )
    .join('');
}

document.getElementById('verify').onclick = async () => {
  const r = await verifyChain();
  alert(r.ok ? `OK · ${r.n} records · head ${r.head}` : `FAIL @${r.at}: ${r.reason}`);
};

document.getElementById('export').onclick = async () => {
  const json = await exportJSON();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  a.download = `surakshanet_${Date.now()}.json`;
  a.click();
};

render();
