/**
 * Incident storage layer.
 *
 * - Standalone mode (no Chrome managed policy): stores locally in chrome.storage.local.
 * - Parent-Locked Vault mode (managed policy lockMode=true + parentPublicKey):
 *     NEVER stores plaintext in browser storage. Deduplicates by hash only,
 *     immediately encrypts with the parent's public key, and streams to the
 *     privileged native Vault Daemon. Clearing or listing plaintext is blocked.
 */
import { getManagedPolicy } from './policy.js';
import { sealAndSendIncident } from './vault_client.js';

const KEY = 'surakshanet_incidents';
const SEEN_HASHES_KEY = 'surakshanet_seen_hashes';
const CAP = 200;

export async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function saveIncident({ text, contact, score, severity }) {
  const chat = typeof contact === 'string' && contact.trim() ? contact.trim() : 'Unknown chat';
  const id = await sha256(`${chat}\n${text.trim().toLowerCase()}`);
  const ts = new Date().toISOString();
  const policy = await getManagedPolicy();

  if (policy.lockMode) {
    const { [SEEN_HASHES_KEY]: seen = [] } = await chrome.storage.local.get(SEEN_HASHES_KEY);
    if (seen.includes(id)) return null;

    const payload = { id, ts, contact: chat, score, severity, text };
    const result = await sealAndSendIncident(payload);

    // Store only one-way SHA-256 deduplication IDs (no plaintext, no contact name).
    seen.unshift(id);
    await chrome.storage.local.set({ [SEEN_HASHES_KEY]: seen.slice(0, CAP * 2) });
    return { id, ts, severity, locked: true, ...result };
  }

  const { [KEY]: list = [] } = await chrome.storage.local.get(KEY);
  if (list.some((x) => x.id === id)) return null;
  const row = { id, ts, contact: chat, score, severity, text, screenshot: null };
  list.unshift(row);
  await chrome.storage.local.set({ [KEY]: list.slice(0, CAP) });
  return row;
}

export async function listIncidents() {
  const policy = await getManagedPolicy();
  if (policy.lockMode) return [];
  const { [KEY]: list = [] } = await chrome.storage.local.get(KEY);
  return list;
}

export async function clearIncidents() {
  const policy = await getManagedPolicy();
  if (policy.lockMode) {
    throw new Error('Cannot clear incidents while Parent-Locked Vault Mode is active.');
  }
  await chrome.storage.local.set({ [KEY]: [] });
}

export async function exportJSON() {
  const policy = await getManagedPolicy();
  if (policy.lockMode) {
    throw new Error('Cannot export plaintext incidents while Parent-Locked Vault Mode is active.');
  }
  return JSON.stringify(
    { exportedAt: new Date().toISOString(), incidents: await listIncidents() },
    null,
    2,
  );
}
