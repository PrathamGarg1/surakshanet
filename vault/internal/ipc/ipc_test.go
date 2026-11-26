package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/PrathamGarg1/surakshanet/vault/internal/chain"
	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
)

func TestDaemonNativeBridgeAndHeartbeatWatchdog(t *testing.T) {
	mat, err := sncrypto.GenerateParentKeyMaterial("Parent")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmp := t.TempDir()
	vaultDir := filepath.Join(tmp, "vault")
	sockPath := filepath.Join(tmp, "vault.sock")

	v, err := chain.InitVault(vaultDir, mat.PublicBundle(), true)
	if err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	defer v.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(v, "unix", sockPath, 120*time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	// Wait briefly for socket to come up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := SendRequest("unix", sockPath, Request{Action: ActionStatus}); err == nil && resp.OK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Prepare Chrome Native Messaging stdin frames: APPEND_INCIDENT, HEARTBEAT, and forbidden DELETE.
	box, err := sncrypto.Seal([]byte(`{"contact":"Stranger","text":"send me your photo"}`), mat.ECDHPublicRaw)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var stdinBuf bytes.Buffer
	requests := []Request{
		{Action: ActionAppendIncident, ExtensionID: "testext123", Sealed: box},
		{Action: ActionHeartbeat, ExtensionID: "testext123"},
		{Action: "DELETE_ALL", ExtensionID: "testext123"},
	}
	for _, r := range requests {
		raw, _ := json.Marshal(r)
		if err := WriteNativeMessage(&stdinBuf, raw); err != nil {
			t.Fatalf("WriteNativeMessage: %v", err)
		}
	}

	var stdoutBuf bytes.Buffer
	if err := RunNativeBridge(&stdinBuf, &stdoutBuf, "unix", sockPath); err != nil {
		t.Fatalf("RunNativeBridge: %v", err)
	}

	// Read 3 native responses back.
	var responses []Response
	for i := 0; i < 3; i++ {
		raw, err := ReadNativeMessage(&stdoutBuf)
		if err != nil {
			t.Fatalf("ReadNativeMessage[%d]: %v", i, err)
		}
		var resp Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatalf("unmarshal response[%d]: %v", i, err)
		}
		responses = append(responses, resp)
	}
	if !responses[0].OK || !responses[1].OK {
		t.Fatalf("expected append and heartbeat to succeed: %+v", responses)
	}
	if responses[2].OK {
		t.Fatalf("expected forbidden DELETE_ALL action to be rejected, got: %+v", responses[2])
	}

	// Wait past heartbeat timeout so watchdog logs TAMPER_HEARTBEAT_GAP.
	time.Sleep(260 * time.Millisecond)
	cancel()
	<-done

	rep, _, err := chain.VerifyVaultDir(vaultDir, true)
	if err != nil {
		t.Fatalf("VerifyVaultDir: %v", err)
	}
	if !rep.OK {
		t.Fatalf("expected valid vault chain, got errors=%v", rep.Errors)
	}
	if rep.IncidentCount != 1 {
		t.Fatalf("expected 1 incident, got %d", rep.IncidentCount)
	}
	if rep.TamperEventCount < 1 {
		t.Fatalf("expected heartbeat watchdog to record at least 1 TAMPER_HEARTBEAT_GAP, got %d", rep.TamperEventCount)
	}
}
