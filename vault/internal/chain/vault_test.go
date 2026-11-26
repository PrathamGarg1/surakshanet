package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
)

func setupTestVault(t *testing.T) (string, *Vault, *sncrypto.ParentKeyMaterial) {
	t.Helper()
	mat, err := sncrypto.GenerateParentKeyMaterial("Parent")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := InitVault(dir, mat.PublicBundle(), true)
	if err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return dir, v, mat
}

func TestVaultChainAndTamperDetection(t *testing.T) {
	dir, v, mat := setupTestVault(t)

	for i := 0; i < 3; i++ {
		box, err := sncrypto.Seal([]byte(`{"text":"abusive test message"}`), mat.ECDHPublicRaw)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if _, err := v.Append(RecordTypeIncident, CallerInfo{UID: 1001, PID: 4242}, box, nil); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	// Reject incident sealed to a foreign parent public key.
	foreign, _ := sncrypto.GenerateParentKeyMaterial("Attacker")
	foreignBox, _ := sncrypto.Seal([]byte(`{"text":"spoof"}`), foreign.ECDHPublicRaw)
	if _, err := v.Append(RecordTypeIncident, CallerInfo{UID: 1001, PID: 4242}, foreignBox, nil); err == nil {
		t.Fatal("expected vault to reject sealed box encrypted for unknown parent key_id")
	}

	// Intact verification must succeed.
	rep, records, err := VerifyVaultDir(dir, true)
	if err != nil {
		t.Fatalf("VerifyVaultDir: %v", err)
	}
	if !rep.OK || !rep.AnchorMatched {
		t.Fatalf("expected intact vault, got errors=%v", rep.Errors)
	}
	if rep.RecordCount != 4 || rep.IncidentCount != 3 || len(records) != 4 {
		t.Fatalf("unexpected counts: records=%d incidents=%d", rep.RecordCount, rep.IncidentCount)
	}

	logPath := filepath.Join(dir, vaultLogFileName)
	origBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	origLines := strings.Split(strings.TrimSpace(string(origBytes)), "\n")

	// Tamper 1: Modify 1 character in record #2.
	editedLines := append([]string(nil), origLines...)
	editedLines[1] = strings.Replace(editedLines[1], `"INCIDENT"`, `"HEARTBEAT"`, 1)
	if err := os.WriteFile(logPath, []byte(strings.Join(editedLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, err = VerifyVaultDir(dir, true)
	if err != nil {
		t.Fatalf("VerifyVaultDir after edit: %v", err)
	}
	if rep.OK {
		t.Fatal("expected VerifyVaultDir to FAIL after middle-record modification")
	}

	// Tamper 2: Delete middle record (#2).
	deletedMiddle := append([]string{origLines[0]}, origLines[2:]...)
	if err := os.WriteFile(logPath, []byte(strings.Join(deletedMiddle, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, err = VerifyVaultDir(dir, true)
	if err != nil {
		t.Fatalf("VerifyVaultDir after middle delete: %v", err)
	}
	if rep.OK {
		t.Fatal("expected VerifyVaultDir to FAIL after middle-record deletion")
	}

	// Tamper 3: Truncate last record (tail deletion — caught by anchor!).
	truncated := origLines[:len(origLines)-1]
	if err := os.WriteFile(logPath, []byte(strings.Join(truncated, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _, err = VerifyVaultDir(dir, true)
	if err != nil {
		t.Fatalf("VerifyVaultDir after truncation: %v", err)
	}
	if rep.OK || rep.AnchorMatched {
		t.Fatalf("expected VerifyVaultDir to FAIL on tail truncation; ok=%v anchorMatched=%v", rep.OK, rep.AnchorMatched)
	}
}
