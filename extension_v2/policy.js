/**
 * Reads Chrome Enterprise Managed Policy (set only by OS Administrator via
 * /etc/opt/chrome/policies/managed/ on Linux or HKLM\SOFTWARE\Policies\Google\Chrome on Windows).
 *
 * Non-admin child accounts cannot modify chrome.storage.managed.
 */

export const DEFAULT_NATIVE_HOST = 'com.surakshanet.vault';
export const DEFAULT_HEARTBEAT_SEC = 60;

export async function getManagedPolicy() {
  const fallback = {
    lockMode: false,
    parentPublicKey: '',
    nativeHostName: DEFAULT_NATIVE_HOST,
    heartbeatSec: DEFAULT_HEARTBEAT_SEC,
  };
  if (!chrome?.storage?.managed) return fallback;
  try {
    const raw = await chrome.storage.managed.get([
      'lockMode',
      'parentPublicKey',
      'nativeHostName',
      'heartbeatSec',
    ]);
    const parentPublicKey = typeof raw.parentPublicKey === 'string' ? raw.parentPublicKey.trim() : '';
    const lockMode = Boolean(raw.lockMode) && parentPublicKey.length > 0;
    const nativeHostName =
      typeof raw.nativeHostName === 'string' && raw.nativeHostName.trim()
        ? raw.nativeHostName.trim()
        : DEFAULT_NATIVE_HOST;
    const heartbeatSec =
      Number.isInteger(raw.heartbeatSec) && raw.heartbeatSec >= 15
        ? raw.heartbeatSec
        : DEFAULT_HEARTBEAT_SEC;

    return { lockMode, parentPublicKey, nativeHostName, heartbeatSec };
  } catch {
    return fallback;
  }
}
