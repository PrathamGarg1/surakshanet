/**
 * Real microbenchmark + artifact capture for SurakshaNet Tamper-Evident Parent Vault.
 *
 * Produces:
 *   - vault/bench_report.json  (exact measured median/p95 latencies across all vault ops)
 *   - Optional artifact export dir (--artifacts-dir <dir>) with real signed PDF & real CLI logs
 */

import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { sealPayload } from '../extension_v2/crypto_seal.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const artifactsIdx = process.argv.indexOf('--artifacts-dir');
const artifactsDir = artifactsIdx !== -1 ? process.argv[artifactsIdx + 1] : null;

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'surakshanet-bench-'));
const binPath = path.join(tmpRoot, 'surakshanet-vault');
const vaultDir = path.join(tmpRoot, 'vault');
const sockPath = path.join(tmpRoot, 'vault.sock');
const parentKeyPath = path.join(tmpRoot, 'parent.key.json');
const parentPubPath = path.join(tmpRoot, 'parent.pub.json');
const parentCertPath = path.join(tmpRoot, 'parent.crt.pem');
const pdfOutPath = path.join(tmpRoot, 'surakshanet-verified-report.pdf');
const jsonOutPath = path.join(tmpRoot, 'surakshanet-verified-report.json');
const passphrase = 'parent-guardian-demo-key';

function stats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const p = (q) => sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * q))];
  const mean = samples.reduce((a, b) => a + b, 0) / samples.length;
  return {
    n: samples.length,
    median_ms: Number(p(0.5).toFixed(2)),
    p95_ms: Number(p(0.95).toFixed(2)),
    mean_ms: Number(mean.toFixed(2)),
  };
}

function frameNativeMessage(obj) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

function sendOneBridge(req) {
  return new Promise((resolve, reject) => {
    const child = spawn(binPath, ['bridge', '--network', 'unix', '--addr', sockPath]);
    const chunks = [];
    child.stdout.on('data', (c) => chunks.push(c));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) return reject(new Error(`bridge exit ${code}`));
      const buf = Buffer.concat(chunks);
      const len = buf.readUInt32LE(0);
      resolve(JSON.parse(buf.subarray(4, 4 + len).toString('utf8')));
    });
    child.stdin.write(frameNativeMessage(req));
    child.stdin.end();
  });
}

let daemon = null;
try {
  execFileSync('go', ['build', '-o', binPath, './cmd/surakshanet-vault'], { cwd: __dirname });

  const initOut = execFileSync(binPath, [
    'init',
    '--vault-dir', vaultDir,
    '--parent-key-out', parentKeyPath,
    '--parent-pub-out', parentPubPath,
    '--parent-cert-out', parentCertPath,
    '--passphrase', passphrase,
    '--no-tpm',
  ], { encoding: 'utf8' });

  const pubBundle = JSON.parse(fs.readFileSync(parentPubPath, 'utf8'));

  daemon = spawn(binPath, [
    'daemon',
    '--vault-dir', vaultDir,
    '--network', 'unix',
    '--addr', sockPath,
    '--heartbeat-timeout', '0',
    '--no-tpm',
  ]);
  for (let i = 0; i < 40; i += 1) {
    if (fs.existsSync(sockPath)) break;
    await new Promise((r) => setTimeout(r, 50));
  }

  // 1. Seed 3 realistic multilingual incidents for report preview.
  const demoIncidents = [
    {
      id: 'demo-1',
      ts: '2026-11-26T13:30:12.000Z',
      contact: 'Unknown Stranger (+91-98xxx)',
      score: 0.97,
      severity: 'high',
      text: 'Do not tell your parents we talk here. Delete this chat and send your photo privately.',
    },
    {
      id: 'demo-2',
      ts: '2026-11-26T13:31:45.000Z',
      contact: 'School Group Chat',
      score: 0.93,
      severity: 'high',
      text: 'tu bilkul bekar hai, kal school mat aana warna sabko tera video dikha dunga',
    },
    {
      id: 'demo-3',
      ts: '2026-11-26T13:34:08.000Z',
      contact: 'Fake Senior Account',
      score: 0.89,
      severity: 'medium',
      text: 'Are you home alone right now? Keep this secret between us only.',
    },
  ];

  const sealedSampleTimes = [];
  const bridgeAppendTimes = [];
  for (const inc of demoIncidents) {
    const t0 = performance.now();
    const sealed = await sealPayload(inc, pubBundle.parent_public_key);
    sealedSampleTimes.push(performance.now() - t0);

    const t1 = performance.now();
    await sendOneBridge({ action: 'APPEND_INCIDENT', ext_id: 'surakshanet-v2', sealed });
    bridgeAppendTimes.push(performance.now() - t1);
  }

  // Capture realistic CLI outputs right after the 3 demo incidents (for clean signed PDF preview!).
  const verifyDemoOut = execFileSync(binPath, ['verify', '--vault-dir', vaultDir, '--no-tpm'], {
    encoding: 'utf8',
  });
  const exportDemoOut = execFileSync(binPath, [
    'export',
    '--vault-dir', vaultDir,
    '--parent-key', parentKeyPath,
    '--passphrase', passphrase,
    '--pdf-out', pdfOutPath,
    '--json-out', jsonOutPath,
    '--no-tpm',
  ], { encoding: 'utf8' });
  const verifyPdfDemoOut = execFileSync(binPath, [
    'verify-pdf',
    '--pdf', pdfOutPath,
    '--cert', parentCertPath,
  ], { encoding: 'utf8' });

  // Capture attack 1: forbidden DELETE over Native Messaging IPC.
  const deleteResp = await sendOneBridge({ action: 'DELETE_ALL', ext_id: 'surakshanet-v2' });

  // Capture attack 2: 1-byte PDF tamper.
  const pdfBytes = fs.readFileSync(pdfOutPath);
  const tamperedPdfPath = path.join(tmpRoot, 'tampered.pdf');
  fs.writeFileSync(
    tamperedPdfPath,
    Buffer.from(pdfBytes.toString('latin1').replace('Delete this chat', 'Keep   this chat'), 'latin1'),
  );
  let pdfTamperErr = '';
  try {
    execFileSync(binPath, ['verify-pdf', '--pdf', tamperedPdfPath, '--cert', parentCertPath], {
      encoding: 'utf8',
      stdio: 'pipe',
    });
  } catch (e) {
    pdfTamperErr = (e.stderr || e.stdout || String(e)).toString().trim();
  }

  if (artifactsDir) {
    fs.mkdirSync(artifactsDir, { recursive: true });
    fs.copyFileSync(pdfOutPath, path.join(artifactsDir, 'surakshanet-verified-report.pdf'));
    fs.copyFileSync(jsonOutPath, path.join(artifactsDir, 'surakshanet-verified-report.json'));
    fs.copyFileSync(parentPubPath, path.join(artifactsDir, 'parent.pub.json'));
  }

  // 2. Run 50 iterations of Web Crypto sealPayload + 50 iterations of bridge APPEND_INCIDENT.
  const payload = {
    id: 'bench-msg',
    ts: '2026-11-26T14:00:00.000Z',
    contact: 'Bench Chat',
    score: 0.94,
    severity: 'high',
    text: 'Sample benchmark abusive message in English and Hinglish for latency measurement.',
  };
  for (let i = 0; i < 50; i += 1) {
    const t0 = performance.now();
    const sealed = await sealPayload({ ...payload, id: `bench-${i}` }, pubBundle.parent_public_key);
    sealedSampleTimes.push(performance.now() - t0);

    const t1 = performance.now();
    const resp = await sendOneBridge({ action: 'APPEND_INCIDENT', ext_id: 'surakshanet-v2', sealed });
    bridgeAppendTimes.push(performance.now() - t1);
    if (!resp.ok) throw new Error(`append failed: ${resp.error}`);
  }

  // 3. Measure verify, export, and verify-pdf across 10 runs on the 55-record vault.
  const verifyTimes = [];
  const exportTimes = [];
  const verifyPdfTimes = [];
  const benchPdf = path.join(tmpRoot, 'bench-55.pdf');
  for (let i = 0; i < 10; i += 1) {
    const tv0 = performance.now();
    execFileSync(binPath, ['verify', '--vault-dir', vaultDir, '--no-tpm'], { stdio: 'pipe' });
    verifyTimes.push(performance.now() - tv0);

    const te0 = performance.now();
    execFileSync(binPath, [
      'export',
      '--vault-dir', vaultDir,
      '--parent-key', parentKeyPath,
      '--passphrase', passphrase,
      '--pdf-out', benchPdf,
      '--no-tpm',
    ], { stdio: 'pipe' });
    exportTimes.push(performance.now() - te0);

    const tp0 = performance.now();
    execFileSync(binPath, ['verify-pdf', '--pdf', benchPdf, '--cert', parentCertPath], { stdio: 'pipe' });
    verifyPdfTimes.push(performance.now() - tp0);
  }

  // Capture attack 3: tail truncation of vault.jsonl.
  daemon.kill('SIGTERM');
  daemon = null;
  const logPath = path.join(vaultDir, 'vault.jsonl');
  const lines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
  fs.writeFileSync(logPath, `${lines.slice(0, -1).join('\n')}\n`);
  let tailTruncErr = '';
  try {
    execFileSync(binPath, ['verify', '--vault-dir', vaultDir, '--no-tpm'], {
      encoding: 'utf8',
      stdio: 'pipe',
    });
  } catch (e) {
    tailTruncErr = ((e.stdout || '') + '\n' + (e.stderr || '')).toString().trim();
  }

  const report = {
    measured_at: new Date().toISOString(),
    platform: `${process.platform}/${process.arch}`,
    node_version: process.version,
    records_in_bench_vault: lines.length,
    sealed_box_js_webcrypto: stats(sealedSampleTimes),
    native_bridge_append_fsync: stats(bridgeAppendTimes),
    vault_verify_cli_55_records: stats(verifyTimes),
    parent_export_scrypt_decrypt_sign_pdf_55_records: stats(exportTimes),
    pdf_pkcs7_verify_cli: stats(verifyPdfTimes),
    demo_transcripts: {
      init: initOut.trim(),
      verify: verifyDemoOut.trim(),
      export: exportDemoOut.trim(),
      verify_pdf: verifyPdfDemoOut.trim(),
      attack_delete_ipc: JSON.stringify(deleteResp),
      attack_pdf_1byte: pdfTamperErr,
      attack_tail_truncation: tailTruncErr,
    },
  };

  fs.writeFileSync(path.join(__dirname, 'bench_report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({
    sealed_box_js_webcrypto: report.sealed_box_js_webcrypto,
    native_bridge_append_fsync: report.native_bridge_append_fsync,
    vault_verify_cli_55_records: report.vault_verify_cli_55_records,
    parent_export_scrypt_decrypt_sign_pdf_55_records: report.parent_export_scrypt_decrypt_sign_pdf_55_records,
    pdf_pkcs7_verify_cli: report.pdf_pkcs7_verify_cli,
  }, null, 2));
} finally {
  if (daemon) daemon.kill('SIGTERM');
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}
