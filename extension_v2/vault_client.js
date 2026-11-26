/**
 * Client for the privileged SurakshaNet Vault Daemon over Chrome Native Messaging.
 *
 * Security invariants in Parent-Locked Mode:
 *  - Plaintext incident messages are NEVER written to chrome.storage.local.
 *  - Every incident is encrypted with the parent's public key (crypto_seal.js) BEFORE leaving memory.
 *  - If the native daemon is temporarily unreachable, ONLY encrypted sealed boxes are buffered
 *    for automatic retry.
 *  - The native IPC protocol is strictly write-only (APPEND_INCIDENT, HEARTBEAT, STATUS).
 */

import { sealPayload } from './crypto_seal.js';
import { getManagedPolicy } from './policy.js';

const PENDING_KEY = 'surakshanet_sealed_pending';
const META_KEY = 'surakshanet_vault_meta';
const MAX_PENDING = 500;

function sendNative(hostName, payload) {
  return new Promise((resolve, reject) => {
    if (!chrome?.runtime?.sendNativeMessage) {
      reject(new Error('chrome.runtime.sendNativeMessage unavailable'));
      return;
    }
    chrome.runtime.sendNativeMessage(hostName, payload, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message || 'Native messaging error'));
        return;
      }
      if (!response || !response.ok) {
        reject(new Error(response?.error || 'Vault daemon rejected request'));
        return;
      }
      resolve(response);
    });
  });
}

async function readMeta() {
  const { [META_KEY]: meta = {} } = await chrome.storage.local.get(META_KEY);
  return {
    sealedCount: Number(meta.sealedCount || 0),
    highRiskCount: Number(meta.highRiskCount || 0),
    lastSeq: Number(meta.lastSeq || 0),
    lastRecordHash: meta.lastRecordHash || '',
    anchorBackend: meta.anchorBackend || 'UNKNOWN',
    parentKeyId: meta.parentKeyId || '',
    vaultConnected: Boolean(meta.vaultConnected),
    lastError: meta.lastError || '',
    lastSyncedAt: meta.lastSyncedAt || null,
  };
}

async function writeMeta(patch) {
  const cur = await readMeta();
  const next = { ...cur, ...patch };
  await chrome.storage.local.set({ [META_KEY]: next });
  return next;
}

export async function getVaultStatus() {
  const policy = await getManagedPolicy();
  const meta = await readMeta();
  const { [PENDING_KEY]: pending = [] } = await chrome.storage.local.get(PENDING_KEY);

  if (policy.lockMode) {
    try {
      const resp = await sendNative(policy.nativeHostName, {
        action: 'STATUS',
        ext_id: chrome.runtime.id,
      });
      const updated = await writeMeta({
        vaultConnected: true,
        lastSeq: resp.seq || meta.lastSeq,
        lastRecordHash: resp.record_hash || meta.lastRecordHash,
        anchorBackend: resp.anchor_backend || meta.anchorBackend,
        parentKeyId: resp.parent_key_id || meta.parentKeyId,
        lastError: '',
      });
      return {
        locked: true,
        pendingCount: pending.length,
        ...updated,
      };
    } catch (error) {
      const updated = await writeMeta({
        vaultConnected: false,
        lastError: String(error?.message || error),
      });
      return {
        locked: true,
        pendingCount: pending.length,
        ...updated,
      };
    }
  }

  return {
    locked: false,
    pendingCount: 0,
    ...meta,
  };
}

export async function sealAndSendIncident(incidentPayload) {
  const policy = await getManagedPolicy();
  if (!policy.lockMode) {
    throw new Error('sealAndSendIncident called outside lockMode');
  }

  // Encrypt immediately using only the parent's public key.
  const sealed = await sealPayload(incidentPayload, policy.parentPublicKey);
  const meta = await readMeta();
  const nextCounts = {
    sealedCount: meta.sealedCount + 1,
    highRiskCount: meta.highRiskCount + (incidentPayload.severity === 'high' ? 1 : 0),
    parentKeyId: sealed.kid,
  };

  try {
    const resp = await sendNative(policy.nativeHostName, {
      action: 'APPEND_INCIDENT',
      ext_id: chrome.runtime.id,
      sealed,
      meta: {
        severity: String(incidentPayload.severity || 'medium'),
      },
    });
    await writeMeta({
      ...nextCounts,
      vaultConnected: true,
      lastSeq: resp.seq,
      lastRecordHash: resp.record_hash,
      anchorBackend: resp.anchor_backend || meta.anchorBackend,
      lastSyncedAt: new Date().toISOString(),
      lastError: '',
    });
    await flushPendingSealed();
    return { delivered: true, seq: resp.seq, recordHash: resp.record_hash, keyId: sealed.kid };
  } catch (error) {
    // Daemon offline: buffer ONLY the encrypted sealed box (never plaintext).
    const { [PENDING_KEY]: pending = [] } = await chrome.storage.local.get(PENDING_KEY);
    pending.push({
      sealed,
      severity: String(incidentPayload.severity || 'medium'),
      queuedAt: new Date().toISOString(),
    });
    await chrome.storage.local.set({ [PENDING_KEY]: pending.slice(-MAX_PENDING) });
    await writeMeta({
      ...nextCounts,
      vaultConnected: false,
      lastError: String(error?.message || error),
    });
    return { delivered: false, queued: true, keyId: sealed.kid };
  }
}

export async function flushPendingSealed() {
  const policy = await getManagedPolicy();
  if (!policy.lockMode) return 0;

  const { [PENDING_KEY]: pending = [] } = await chrome.storage.local.get(PENDING_KEY);
  if (!pending.length) return 0;

  let flushed = 0;
  const remaining = [];
  for (let i = 0; i < pending.length; i += 1) {
    const item = pending[i];
    try {
      const resp = await sendNative(policy.nativeHostName, {
        action: 'APPEND_INCIDENT',
        ext_id: chrome.runtime.id,
        sealed: item.sealed,
        meta: {
          severity: item.severity || 'medium',
          queued_at: item.queuedAt || '',
        },
      });
      flushed += 1;
      await writeMeta({
        vaultConnected: true,
        lastSeq: resp.seq,
        lastRecordHash: resp.record_hash,
        anchorBackend: resp.anchor_backend || 'UNKNOWN',
        lastSyncedAt: new Date().toISOString(),
        lastError: '',
      });
    } catch (error) {
      remaining.push(...pending.slice(i));
      await writeMeta({
        vaultConnected: false,
        lastError: String(error?.message || error),
      });
      break;
    }
  }
  await chrome.storage.local.set({ [PENDING_KEY]: remaining });
  return flushed;
}

export async function sendHeartbeat() {
  const policy = await getManagedPolicy();
  if (!policy.lockMode) return null;

  try {
    await flushPendingSealed();
    const resp = await sendNative(policy.nativeHostName, {
      action: 'HEARTBEAT',
      ext_id: chrome.runtime.id,
      meta: {
        version: chrome.runtime.getManifest().version,
      },
    });
    await writeMeta({
      vaultConnected: true,
      lastSeq: resp.seq,
      lastRecordHash: resp.record_hash,
      anchorBackend: resp.anchor_backend || 'UNKNOWN',
      parentKeyId: resp.parent_key_id || '',
      lastSyncedAt: new Date().toISOString(),
      lastError: '',
    });
    return resp;
  } catch (error) {
    await writeMeta({
      vaultConnected: false,
      lastError: String(error?.message || error),
    });
    return null;
  }
}
