#!/usr/bin/env bash
set -euo pipefail

# SurakshaNet Parent-Locked Vault Uninstaller (Linux, root only)
if [[ "${EUID}" -ne 0 ]]; then
  echo "Error: run this uninstaller as root (sudo)." >&2
  exit 1
fi

echo "Stopping surakshanet-vault service..."
systemctl disable --now surakshanet-vault.service 2>/dev/null || true
rm -f /etc/systemd/system/surakshanet-vault.service
systemctl daemon-reload || true

echo "Removing Chrome / Chromium managed policies and native host manifests..."
rm -f /etc/opt/chrome/policies/managed/surakshanet.json \
      /etc/chromium/policies/managed/surakshanet.json \
      /etc/opt/chrome/native-messaging-hosts/com.surakshanet.vault.json \
      /etc/chromium/native-messaging-hosts/com.surakshanet.vault.json

rm -f /usr/local/bin/surakshanet-vault /usr/local/bin/surakshanet-vault-bridge

echo "Done. Note: /var/lib/surakshanet/vault was intentionally PRESERVED so evidence is not lost."
echo "To delete preserved evidence (after exporting signed PDF), run: sudo chattr -a /var/lib/surakshanet/vault/vault.jsonl && sudo rm -rf /var/lib/surakshanet"
