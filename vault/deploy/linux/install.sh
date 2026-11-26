#!/usr/bin/env bash
set -euo pipefail

# SurakshaNet Parent-Locked Vault Installer (Linux)
# Must be run as root (sudo) by the Parent Administrator.
#
# Usage:
#   sudo EXT_ID="<32-char-chrome-extension-id>" \
#        EXT_UPDATE_URL="https://clients2.google.com/service/update2/crx" \
#        PARENT_KEY_OUT="/media/parent-usb/parent.key.json" \
#        SURAKSHANET_PASSPHRASE="your-strong-passphrase" \
#        bash vault/deploy/linux/install.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: run this installer as root (sudo) from the Parent Admin account." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

EXT_ID="${EXT_ID:-}"
EXT_UPDATE_URL="${EXT_UPDATE_URL:-https://clients2.google.com/service/update2/crx}"
PARENT_KEY_OUT="${PARENT_KEY_OUT:-/root/surakshanet-parent.key.json}"
PARENT_LABEL="${PARENT_LABEL:-SurakshaNet Parent Guardian}"
VAULT_DIR="/var/lib/surakshanet/vault"
BIN_PATH="/usr/local/bin/surakshanet-vault"
BRIDGE_WRAPPER="/usr/local/bin/surakshanet-vault-bridge"

if [[ -z "${EXT_ID}" ]]; then
  echo "Error: EXT_ID is required (the 32-character Chrome extension ID)." >&2
  exit 1
fi

if [[ -z "${SURAKSHANET_PASSPHRASE:-}" ]]; then
  read -rsp "Enter passphrase (>=8 chars) to encrypt Parent Private Key: " SURAKSHANET_PASSPHRASE
  echo
  export SURAKSHANET_PASSPHRASE
fi

echo "[1/5] Building surakshanet-vault binary..."
(cd "${VAULT_ROOT}" && go build -o "${BIN_PATH}" ./cmd/surakshanet-vault)
chown root:root "${BIN_PATH}"
chmod 0755 "${BIN_PATH}"

cat > "${BRIDGE_WRAPPER}" <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/surakshanet-vault bridge --network unix --addr /run/surakshanet/vault.sock "$@"
EOF
chown root:root "${BRIDGE_WRAPPER}"
chmod 0755 "${BRIDGE_WRAPPER}"

echo "[2/5] Initializing admin-only vault and Parent keypair..."
mkdir -p /var/lib/surakshanet
chown root:root /var/lib/surakshanet
chmod 0700 /var/lib/surakshanet

PUB_JSON="/var/lib/surakshanet/parent.pub.json"
CERT_PEM="/var/lib/surakshanet/parent.crt.pem"

if [[ ! -f "${VAULT_DIR}/vault.config.json" ]]; then
  "${BIN_PATH}" init \
    --vault-dir "${VAULT_DIR}" \
    --parent-key-out "${PARENT_KEY_OUT}" \
    --parent-pub-out "${PUB_JSON}" \
    --parent-cert-out "${CERT_PEM}" \
    --label "${PARENT_LABEL}"
else
  echo "  Vault already exists at ${VAULT_DIR}; reusing existing public key."
fi

PARENT_PUB_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["parent_public_key"])' "${PUB_JSON}")"

echo "[3/5] Installing Chrome / Chromium Enterprise Managed Policies (admin-locked)..."
POLICY_JSON="$(cat <<EOF
{
  "ExtensionInstallForcelist": [
    "${EXT_ID};${EXT_UPDATE_URL}"
  ],
  "DeveloperToolsAvailability": 2,
  "IncognitoModeAvailability": 1,
  "3rdparty": {
    "extensions": {
      "${EXT_ID}": {
        "lockMode": true,
        "parentPublicKey": "${PARENT_PUB_KEY}",
        "nativeHostName": "com.surakshanet.vault",
        "heartbeatSec": 60
      }
    }
  }
}
EOF
)"

for policy_dir in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed; do
  mkdir -p "${policy_dir}"
  printf '%s\n' "${POLICY_JSON}" > "${policy_dir}/surakshanet.json"
  chown root:root "${policy_dir}/surakshanet.json"
  chmod 0644 "${policy_dir}/surakshanet.json"
done

echo "[4/5] Registering system-wide Native Messaging Host (root-owned)..."
NM_MANIFEST="$(cat <<EOF
{
  "name": "com.surakshanet.vault",
  "description": "SurakshaNet Tamper-Evident Evidence Vault Native Bridge",
  "path": "${BRIDGE_WRAPPER}",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://${EXT_ID}/"
  ]
}
EOF
)"

for nm_dir in /etc/opt/chrome/native-messaging-hosts /etc/chromium/native-messaging-hosts; do
  mkdir -p "${nm_dir}"
  printf '%s\n' "${NM_MANIFEST}" > "${nm_dir}/com.surakshanet.vault.json"
  chown root:root "${nm_dir}/com.surakshanet.vault.json"
  chmod 0644 "${nm_dir}/com.surakshanet.vault.json"
done

echo "[5/5] Installing and starting systemd service..."
cp "${SCRIPT_DIR}/surakshanet-vault.service" /etc/systemd/system/surakshanet-vault.service
chmod 0644 /etc/systemd/system/surakshanet-vault.service
systemctl daemon-reload
systemctl enable --now surakshanet-vault.service

echo ""
echo "========================================================================"
echo "SurakshaNet Parent-Locked Vault installed successfully!"
echo "  Vault directory (root-only): ${VAULT_DIR}"
echo "  Parent Private Key saved to: ${PARENT_KEY_OUT}"
echo "  IMPORTANT: Move ${PARENT_KEY_OUT} to a USB drive or parent device,"
echo "             and keep the child on a Standard (non-sudo) OS account."
echo "  Restart Chrome for managed policies to take effect."
echo "========================================================================"
