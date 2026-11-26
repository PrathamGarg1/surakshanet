# SurakshaNet Tamper-Evident Parent Vault

Privileged, append-only, public-key encrypted evidence vault for `extension_v2/`.

## Architecture

1. **Chrome Enterprise Policy Lock (`deploy/linux/install.sh`, `deploy/windows/install.ps1`)**
   - Force-installs `extension_v2` via `ExtensionInstallForcelist` so a standard (non-admin) child OS user cannot uninstall or disable it.
   - Disables DevTools (`DeveloperToolsAvailability = 2`) and Incognito (`IncognitoModeAvailability = 1`).
   - Injects `lockMode: true` and **only** the Parent's **Public Key** (`parentPublicKey`) into `chrome.storage.managed`.
2. **Sealed-Box Encryption in Extension (`extension_v2/crypto_seal.js`, `vault_client.js`)**
   - Uses Web Crypto API (`ECDH P-256 ephemeral + HKDF-SHA256 + AES-256-GCM`) to encrypt every flagged incident immediately to `PK_parent`.
   - Plaintext messages are **never** written to `chrome.storage.local` in locked mode; if the daemon is offline, only ciphertext is queued.
   - Hides the Clear/Export controls and plaintext log in `popup.js`.
3. **Privileged Write-Only Vault Daemon (`cmd/surakshanet-vault`)**
   - Runs as `root` (Linux `systemd`) or `NT AUTHORITY\SYSTEM` (Windows Task/Service).
   - Accepts strictly write-only IPC (`APPEND_INCIDENT`, `HEARTBEAT`, `STATUS`) from the Chrome Native Messaging bridge (`surakshanet-vault bridge`); no read, list, clear, or delete RPCs exist.
   - Appends every record to an admin-only `vault.jsonl` (`0700 root:root` + Linux `FS_APPEND_FL` / `chattr +a` where supported; locked NTFS ACLs on Windows).
   - Signs every record hash with a daemon-only Ed25519 key and links each entry in a SHA-256 hash chain.
   - Anchors the cumulative digest & monotonic counter into **TPM 2.0 NVRAM** (`github.com/google/go-tpm`, NV indices `0x01500042` / `0x01500043`) when a TPM 2.0 device is present, or transparently falls back to an admin-only anchor file (`ADMIN_FILE_ANCHOR`).
   - Watchdog automatically logs `TAMPER_HEARTBEAT_GAP` if the extension stops sending heartbeats.
4. **Parent Verification & Digitally Signed PDF (`surakshanet-vault export` & `verify-pdf`)**
   - Parent unlocks with `parent.key.json` (kept off the child's account on USB/parent device) + passphrase.
   - Verifies the entire hash chain, daemon Ed25519 signatures, and TPM/anchor digest, then decrypts incidents and emits a **PKCS#7 (`/adbe.pkcs7.detached`) digitally signed PDF**.

## Quick Test (No Root Required)

```bash
cd vault
go test ./...
node e2e_test.mjs
```

## CLI Usage

```bash
# 1. One-time parent setup (Admin / sudo)
sudo EXT_ID="<32-char-extension-id>" \
     PARENT_KEY_OUT="/media/parent-usb/parent.key.json" \
     bash vault/deploy/linux/install.sh

# 2. Verify vault integrity anytime (does not require parent private key)
sudo surakshanet-vault verify --vault-dir /var/lib/surakshanet/vault

# 3. Parent decrypt + export digitally signed PDF
sudo surakshanet-vault export \
  --vault-dir /var/lib/surakshanet/vault \
  --parent-key /media/parent-usb/parent.key.json \
  --pdf-out ./evidence-report.pdf \
  --json-out ./evidence-report.json

# 4. Verify exported PDF signature (catches any 1-byte edit)
surakshanet-vault verify-pdf \
  --pdf ./evidence-report.pdf \
  --cert /var/lib/surakshanet/parent.crt.pem
```
