/**
 * SurakshaNet Sealed-Box Encryption (Web Crypto API).
 *
 * Byte-for-byte interoperable with vault/internal/crypto/sealedbox.go:
 *   ECDH P-256 (ephemeral) + HKDF-SHA256 + AES-256-GCM
 *
 * Only the parent's PUBLIC key is present inside the browser extension.
 * Once sealPayload() returns, the ephemeral private key is unreachable and
 * neither the extension nor the child's OS account can decrypt the record.
 */

const SEALED_BOX_VERSION = 1;
const SEALED_BOX_ALG = 'ECDH-P256-HKDF-SHA256-AES256GCM';
const HKDF_INFO = 'surakshanet-sealedbox-v1';

const encoder = new TextEncoder();

function toBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export async function keyFingerprint(pubRawBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', pubRawBytes));
  return [...digest.subarray(0, 8)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function sealPayload(payloadObject, parentPublicKeyBase64) {
  if (typeof parentPublicKeyBase64 !== 'string' || !parentPublicKeyBase64.trim()) {
    throw new Error('Parent public key is required to seal incident');
  }
  const recipientPubRaw = fromBase64(parentPublicKeyBase64.trim());
  if (recipientPubRaw.length !== 65 || recipientPubRaw[0] !== 0x04) {
    throw new Error('Parent public key must be a 65-byte uncompressed P-256 point');
  }

  const recipientPubKey = await crypto.subtle.importKey(
    'raw',
    recipientPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );

  const ephPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );

  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephPair.publicKey));
  const sharedBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: recipientPubKey },
      ephPair.privateKey,
      256,
    ),
  );

  const salt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', concatBytes(ephPubRaw, recipientPubRaw)),
  );

  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const infoBytes = encoder.encode(HKDF_INFO);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: infoBytes },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aad = concatBytes(infoBytes, ephPubRaw, recipientPubRaw);
  const plaintext = encoder.encode(JSON.stringify(payloadObject));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, aesKey, plaintext),
  );

  return {
    v: SEALED_BOX_VERSION,
    alg: SEALED_BOX_ALG,
    kid: await keyFingerprint(recipientPubRaw),
    epk: toBase64(ephPubRaw),
    nonce: toBase64(nonce),
    ct: toBase64(ct),
  };
}
