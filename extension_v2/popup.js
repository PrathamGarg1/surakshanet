import { listIncidents, clearIncidents, exportJSON } from './store.js';
import { exportIncidentsPDF } from './pdf_exporter.js';
import { getVaultStatus } from './vault_client.js';

const listEl = document.getElementById('list');
const countEl = document.getElementById('incident-count');
const highCountEl = document.getElementById('high-count');
const modeBadgeEl = document.getElementById('mode-badge');
const modeLabelEl = document.getElementById('mode-label');
const sectionTitleEl = document.getElementById('section-title');
const sectionMetaEl = document.getElementById('section-meta');
const actionsEl = document.getElementById('actions');

function formatTimestamp(value) {
  try {
    return new Date(value).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
  } catch {
    return 'Unknown time';
  }
}

function row(item) {
  const article = document.createElement('article');
  article.className = 'row';

  const top = document.createElement('div');
  top.className = 'row-top';

  const contact = document.createElement('h2');
  contact.className = 'contact';
  contact.textContent = item.contact || 'Unknown chat';

  const severity = document.createElement('span');
  severity.className = `severity ${item.severity || 'medium'}`;
  severity.textContent = item.severity || 'medium';

  const meta = document.createElement('div');
  meta.className = 'meta';
  const score = Math.round((Number(item.score) || 0) * 100);
  meta.textContent = `${formatTimestamp(item.ts)} · ${score}% confidence`;

  const message = document.createElement('p');
  message.className = 'message';
  message.textContent = item.text || '';

  top.append(contact, severity);
  article.append(top, meta, message);
  return article;
}

function renderLockedStatus(status) {
  modeBadgeEl.textContent = 'LOCKED';
  modeLabelEl.textContent = status.vaultConnected ? 'Vault active' : 'Vault queued';
  countEl.textContent = status.sealedCount;
  highCountEl.textContent = status.highRiskCount;
  sectionTitleEl.textContent = 'Parent-Locked Vault';
  sectionMetaEl.textContent = status.parentKeyId ? `Key ${status.parentKeyId}` : 'Protected';
  actionsEl.style.display = 'none';

  listEl.innerHTML = '';
  const card = document.createElement('div');
  card.className = 'empty';
  const badge = document.createElement('span');
  badge.className = 'empty-mark';
  badge.setAttribute('aria-hidden', 'true');
  badge.textContent = status.vaultConnected ? '✓' : '!';

  const title = document.createElement('strong');
  title.textContent = status.vaultConnected
    ? 'Tamper-Evident Parent Vault Active'
    : 'Vault Daemon Offline (Buffering Encrypted Blobs)';

  const detail = document.createElement('span');
  detail.textContent =
    'Flagged messages are encrypted immediately with the Parent Public Key and stored in an admin-only append-only vault. Records cannot be viewed or deleted from this account.';

  const meta = document.createElement('span');
  meta.className = 'meta';
  meta.textContent = `Anchor: ${status.anchorBackend} · Chain Seq #${status.lastSeq} · Queued: ${status.pendingCount}`;

  card.append(badge, title, detail, meta);
  listEl.append(card);
}

async function render() {
  const status = await getVaultStatus();
  if (status.locked) {
    renderLockedStatus(status);
    return;
  }

  actionsEl.style.display = '';
  modeBadgeEl.textContent = 'LOCAL';
  modeLabelEl.textContent = 'Processing';
  sectionTitleEl.textContent = 'Incident log';
  sectionMetaEl.textContent = 'Newest first';

  const items = await listIncidents();
  countEl.textContent = items.length;
  highCountEl.textContent = items.filter((item) => item.severity === 'high').length;
  listEl.innerHTML = '';
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'empty';
    empty.innerHTML =
      '<span class="empty-mark" aria-hidden="true">✓</span><strong>No incidents yet</strong><span>SurakshaNet is watching incoming WhatsApp messages on this device.</span>';
    listEl.appendChild(empty);
    return;
  }
  items.forEach((i) => listEl.appendChild(row(i)));
}

document.getElementById('export').onclick = async () => {
  const url = URL.createObjectURL(new Blob([await exportJSON()], { type: 'application/json' }));
  Object.assign(document.createElement('a'), {
    href: url,
    download: `surakshanet-${Date.now()}.json`,
  }).click();
  URL.revokeObjectURL(url);
};

document.getElementById('export-pdf').onclick = async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    const items = await listIncidents();
    if (!items.length) {
      alert('No flagged messages to export.');
      return;
    }
    await exportIncidentsPDF(items);
  } finally {
    button.disabled = false;
  }
};

document.getElementById('clear').onclick = async () => {
  if (!confirm('Clear all local incidents?')) return;
  await clearIncidents();
  render();
};

render();
