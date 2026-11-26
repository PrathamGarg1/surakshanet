/**
 * End-to-End Cross-Language Verification Test
 *
 * Tests the full SurakshaNet Parent-Locked Vault pipeline across JavaScript (Web Crypto API)
 * and Go (privileged vault daemon + Chrome Native Messaging bridge + PKCS#7 signed PDF):
 *   1. `surakshanet-vault init` generates Parent keypair + vault
 *   2. Starts `surakshanet-vault daemon` on a temporary Unix domain socket
 *   3. `extension_v2/crypto_seal.js` encrypts English + Hindi + Hinglish incidents with PK_parent
 *   4. Sends Chrome Native Messaging binary frames through `surakshanet-vault bridge`
 *   5. Confirms forbidden DELETE_ALL action is rejected
 *   6. Runs `surakshanet-vault verify` -> PASS
 *   7. Runs `surakshanet-vault export` -> decrypts exact UTF-8 messages & signs PDF
 *   8. Runs `surakshanet-vault verify-pdf` -> PASS
 *   9. Tampers 1 byte in PDF -> `verify-pdf` FAILS
 *  10. Truncates last line in vault.jsonl -> `verify` FAILS (anchor catches tail truncation)
 */

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sealPayload } from '../extension_v2/crypto_seal.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'surakshanet-e2e-'));
const binPath = path.join(tmpRoot, 'surakshanet-vault');
const vaultDir = path.join(tmpRoot, 'vault');
const sockPath = path.join(tmpRoot, 'vault.sock');
const parentKeyPath = path.join(tmpRoot, 'parent.key.json');
const parentPubPath = path.join(tmpRoot, 'parent.pub.json');
const parentCertPath = path.join(tmpRoot, 'parent.crt.pem');
const pdfOutPath = path.join(tmpRoot, 'evidence.pdf');
const jsonOutPath = path.join(tmpRoot, 'evidence.json');
const passphrase = 'parent-super-secret-passphrase';

function frameNativeMessage(obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

function parseNativeMessages(buf) {
  const out = [];
  let offset = 0;
  while (offset < buf.length) {
    const len = buf.readUInt32LE(offset);
    offset += 4;
    const body = buf.subarray(offset, offset + len).toString('utf8');
    offset += len;
    out.push(JSON.parse(body));
  }
  return out;
}

function sendViaBridge(requests) {
  return new Promise((resolve, reject) => {
    const child = spawn(binPath, ['bridge', '--network', 'unix', '--addr', sockPath]);
    const chunks = [];
    let stderr = '';
    child.stdout.on('data', (c) => chunks.push(c));
    child.stderr.on('data', (c) => {
      stderr += c.toString();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`bridge exited ${code}: ${stderr}`));
        return;
      }
      resolve(parseNativeMessages(Buffer.concat(chunks)));
    });
    for (const req of requests) {
      child.stdin.write(frameNativeMessage(req));
    }
    child.stdin.end();
  });
}

let daemon = null;
try {
  console.log('[1/9] Building surakshanet-vault Go binary...');
  execFileSync('go', ['build', '-o', binPath, './cmd/surakshanet-vault'], { cwd: __dirname });

  console.log('[2/9] Running surakshanet-vault init...');
  execFileSync(binPath, [
    'init',
    '--vault-dir', vaultDir,
    '--parent-key-out', parentKeyPath,
    '--parent-pub-out', parentPubPath,
    '--parent-cert-out', parentCertPath,
    '--passphrase', passphrase,
    '--no-tpm',
  ]);
  const pubBundle = JSON.parse(fs.readFileSync(parentPubPath, 'utf8'));
  assert.ok(pubBundle.parent_public_key, 'parent_public_key missing');

  console.log('[3/9] Starting privileged vault daemon...');
  daemon = spawn(binPath, [
    'daemon',
    '--vault-dir', vaultDir,
    '--network', 'unix',
    '--addr', sockPath,
    '--heartbeat-timeout', '0',
    '--no-tpm',
  ]);

  // Wait for Unix socket readiness.
  for (let i = 0; i < 40; i += 1) {
    if (fs.existsSync(sockPath)) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(fs.existsSync(sockPath), 'daemon socket did not appear');

  console.log('[4/9] Sealing English + Hindi + Hinglish incidents in JS (Web Crypto)...');
  const testIncidents = [
    {
      id: 'inc-en-1',
      ts: '2026-11-26T13:30:00.000Z',
      contact: 'Unknown Stranger',
      score: 0.97,
      severity: 'high',
      text: 'Do not tell your parents we talk here, delete this chat right now.',
    },
    {
      id: 'inc-hi-2',
      ts: '2026-11-26T13:31:00.000Z',
      contact: 'Bully Group',
      score: 0.92,
      severity: 'high',
      text: 'तुम बहुत बेकार हो, कल स्कूल मत आना',
    },
    {
      id: 'inc-hinglish-3',
      ts: '2026-11-26T13:32:00.000Z',
      contact: 'Fake Friend',
      score: 0.84,
      severity: 'medium',
      text: 'apni photo bhej jaldi warna sabko bata dunga',
    },
  ];

  const bridgeReqs = [];
  for (const inc of testIncidents) {
    const sealed = await sealPayload(inc, pubBundle.parent_public_key);
    assert.equal(sealed.kid, pubBundle.key_id);
    // Ensure ciphertext contains zero plaintext substring.
    assert.ok(!JSON.stringify(sealed).includes(inc.text), 'plaintext leaked into sealed box!');
    bridgeReqs.push({ action: 'APPEND_INCIDENT', ext_id: 'surakshanet-test-ext', sealed });
  }
  bridgeReqs.push({ action: 'HEARTBEAT', ext_id: 'surakshanet-test-ext' });
  bridgeReqs.push({ action: 'DELETE', ext_id: 'surakshanet-test-ext' });

  console.log('[5/9] Streaming Chrome Native Messaging frames via bridge...');
  const bridgeResps = await sendViaBridge(bridgeReqs);
  assert.equal(bridgeResps.length, 5);
  assert.equal(bridgeResps[0].ok, true);
  assert.equal(bridgeResps[1].ok, true);
  assert.equal(bridgeResps[2].ok, true);
  assert.equal(bridgeResps[3].ok, true);
  assert.equal(bridgeResps[4].ok, false, 'forbidden DELETE action must be rejected');

  console.log('[6/9] Verifying intact vault hash chain & anchor...');
  const verifyOut = execFileSync(binPath, ['verify', '--vault-dir', vaultDir, '--no-tpm', '--json'], {
    encoding: 'utf8',
  });
  const verifyReport = JSON.parse(verifyOut);
  assert.equal(verifyReport.ok, true);
  assert.equal(verifyReport.anchor_matched, true);
  assert.equal(verifyReport.incident_count, 3);

  console.log('[7/9] Exporting parent-decrypted JSON + PKCS#7 signed PDF...');
  execFileSync(binPath, [
    'export',
    '--vault-dir', vaultDir,
    '--parent-key', parentKeyPath,
    '--passphrase', passphrase,
    '--pdf-out', pdfOutPath,
    '--json-out', jsonOutPath,
    '--no-tpm',
  ]);
  const exported = JSON.parse(fs.readFileSync(jsonOutPath, 'utf8'));
  assert.equal(exported.incidents.length, 3);
  for (let i = 0; i < testIncidents.length; i += 1) {
    assert.equal(exported.incidents[i].text, testIncidents[i].text, `UTF-8 parity mismatch at index ${i}`);
    assert.equal(exported.incidents[i].contact, testIncidents[i].contact);
  }

  console.log('[8/9] Verifying PKCS#7 PDF signature & testing 1-byte PDF tamper rejection...');
  execFileSync(binPath, ['verify-pdf', '--pdf', pdfOutPath, '--cert', parentCertPath]);

  const pdfBytes = fs.readFileSync(pdfOutPath);
  const tamperedPdf = Buffer.from(pdfBytes.toString('latin1').replace('delete this chat', 'keep   this chat'), 'latin1');
  const tamperedPdfPath = path.join(tmpRoot, 'tampered.pdf');
  fs.writeFileSync(tamperedPdfPath, tamperedPdf);
  let pdfTamperCaught = false;
  try {
    execFileSync(binPath, ['verify-pdf', '--pdf', tamperedPdfPath, '--cert', parentCertPath], { stdio: 'pipe' });
  } catch {
    pdfTamperCaught = true;
  }
  assert.equal(pdfTamperCaught, true, '1-byte tampered PDF must fail verification');

  console.log('[9/9] Simulating tail truncation on vault.jsonl and asserting tamper detection...');
  daemon.kill('SIGTERM');
  daemon = null;
  const logPath = path.join(vaultDir, 'vault.jsonl');
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
  fs.writeFileSync(logPath, `${lines.slice(0, -1).join('\n')}\n`);

  let truncationCaught = false;
  try {
    execFileSync(binPath, ['verify', '--vault-dir', vaultDir, '--no-tpm'], { stdio: 'pipe' });
  } catch {
    truncationCaught = true;
  }
  assert.equal(truncationCaught, true, 'tail truncation must fail verification');

  console.log('E2E PARITY & TAMPER-DETECTION TEST PASSED!');
} finally {
  if (daemon) daemon.kill('SIGTERM');
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
