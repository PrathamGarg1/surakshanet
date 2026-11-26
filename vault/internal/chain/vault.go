package chain

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
	"github.com/PrathamGarg1/surakshanet/vault/internal/tpm"
)

const (
	RecordTypeVaultInit    = "VAULT_INIT"
	RecordTypeIncident     = "INCIDENT"
	RecordTypeHeartbeat    = "HEARTBEAT"
	RecordTypeTamperGap    = "TAMPER_HEARTBEAT_GAP"
	RecordTypeDaemonStart  = "DAEMON_START"
	GenesisPrevHash        = "0000000000000000000000000000000000000000000000000000000000000000"
	vaultLogFileName       = "vault.jsonl"
	daemonKeyFileName      = "daemon.ed25519.json"
	vaultConfigFileName    = "vault.config.json"
)

// CallerInfo records OS-verified caller credentials (from SO_PEERCRED / pipe PID).
type CallerInfo struct {
	UID         int    `json:"uid"`
	PID         int    `json:"pid"`
	ExtensionID string `json:"ext_id,omitempty"`
}

// VaultRecord is one immutable line in vault.jsonl.
type VaultRecord struct {
	Seq        uint64              `json:"seq"`
	Type       string              `json:"type"`
	RecordedAt string              `json:"recorded_at"`
	Caller     CallerInfo          `json:"caller"`
	Sealed     *sncrypto.SealedBox `json:"sealed,omitempty"`
	Meta       map[string]string   `json:"meta,omitempty"`
	PrevHash   string              `json:"prev_hash"`
	RecordHash string              `json:"record_hash"`
	DaemonSig  string              `json:"daemon_sig"`
}

// VaultConfig holds non-secret public parameters stored inside the admin vault dir.
type VaultConfig struct {
	Version         int    `json:"version"`
	ParentKeyID     string `json:"parent_key_id"`
	ParentPublicKey string `json:"parent_public_key"`
	DaemonPublicKey string `json:"daemon_public_key"`
	CreatedAt       string `json:"created_at"`
}

type daemonKeyFile struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// Vault manages an append-only, Ed25519-signed, SHA-256 hash-chained log
// anchored into either TPM 2.0 NVRAM or an admin-only anchor file.
type Vault struct {
	mu               sync.Mutex
	dir              string
	logPath          string
	config           VaultConfig
	daemonPriv       ed25519.PrivateKey
	daemonPub        ed25519.PublicKey
	anchor           tpm.Anchor
	anchorNote       string
	appendOnlyKernel bool
	lastSeq          uint64
	lastHash         string
}

// VerificationReport summarizes integrity checks across every record and anchor.
type VerificationReport struct {
	OK                 bool     `json:"ok"`
	RecordCount        uint64   `json:"record_count"`
	IncidentCount      uint64   `json:"incident_count"`
	TamperEventCount   uint64   `json:"tamper_event_count"`
	HeadHash           string   `json:"head_hash"`
	CumulativeDigest   string   `json:"cumulative_digest"`
	AnchorBackend      string   `json:"anchor_backend"`
	AnchorMatched      bool     `json:"anchor_matched"`
	DaemonPubKey       string   `json:"daemon_public_key"`
	ParentKeyID        string   `json:"parent_key_id"`
	Errors             []string `json:"errors,omitempty"`
	Warnings           []string `json:"warnings,omitempty"`
}

// InitVault initializes a brand-new admin-only vault directory, daemon Ed25519
// signing key, vault config, and genesis VAULT_INIT record.
func InitVault(dir string, parentPub *sncrypto.ParentPublicBundle, forceFileAnchor bool) (*Vault, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create vault dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)

	logPath := filepath.Join(dir, vaultLogFileName)
	if _, err := os.Stat(logPath); err == nil {
		return nil, fmt.Errorf("vault already initialized at %s (refusing to overwrite)", logPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate daemon signing key: %w", err)
	}

	dkf := daemonKeyFile{
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}
	dkBytes, err := json.MarshalIndent(dkf, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, daemonKeyFileName), dkBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write daemon key: %w", err)
	}

	cfg := VaultConfig{
		Version:         1,
		ParentKeyID:     parentPub.KeyID,
		ParentPublicKey: parentPub.ParentPublicKey,
		DaemonPublicKey: base64.StdEncoding.EncodeToString(pub),
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	cfgBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, vaultConfigFileName), cfgBytes, 0o600); err != nil {
		return nil, fmt.Errorf("write vault config: %w", err)
	}

	anchor, note := tpm.OpenAnchor(dir, forceFileAnchor)
	v := &Vault{
		dir:        dir,
		logPath:    logPath,
		config:     cfg,
		daemonPriv: priv,
		daemonPub:  pub,
		anchor:     anchor,
		anchorNote: note,
		lastSeq:    0,
		lastHash:   GenesisPrevHash,
	}

	if _, err := v.Append(RecordTypeVaultInit, CallerInfo{UID: os.Getuid(), PID: os.Getpid()}, nil, map[string]string{
		"parent_key_id":  parentPub.KeyID,
		"anchor_backend": anchor.Backend(),
	}); err != nil {
		_ = anchor.Close()
		return nil, fmt.Errorf("append genesis record: %w", err)
	}
	return v, nil
}

// OpenVault loads an existing vault directory and verifies its current tip
// before allowing new appends.
func OpenVault(dir string, forceFileAnchor bool) (*Vault, error) {
	cfgBytes, err := os.ReadFile(filepath.Join(dir, vaultConfigFileName))
	if err != nil {
		return nil, fmt.Errorf("read vault config: %w", err)
	}
	var cfg VaultConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, fmt.Errorf("parse vault config: %w", err)
	}

	dkBytes, err := os.ReadFile(filepath.Join(dir, daemonKeyFileName))
	if err != nil {
		return nil, fmt.Errorf("read daemon key: %w", err)
	}
	var dkf daemonKeyFile
	if err := json.Unmarshal(dkBytes, &dkf); err != nil {
		return nil, fmt.Errorf("parse daemon key: %w", err)
	}
	pubRaw, err := base64.StdEncoding.DecodeString(dkf.PublicKey)
	if err != nil {
		return nil, err
	}
	privRaw, err := base64.StdEncoding.DecodeString(dkf.PrivateKey)
	if err != nil {
		return nil, err
	}

	anchor, note := tpm.OpenAnchor(dir, forceFileAnchor)
	v := &Vault{
		dir:        dir,
		logPath:    filepath.Join(dir, vaultLogFileName),
		config:     cfg,
		daemonPriv: ed25519.PrivateKey(privRaw),
		daemonPub:  ed25519.PublicKey(pubRaw),
		anchor:     anchor,
		anchorNote: note,
		lastHash:   GenesisPrevHash,
	}

	records, err := ReadAllRecords(v.logPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = anchor.Close()
		return nil, err
	}
	if len(records) > 0 {
		last := records[len(records)-1]
		v.lastSeq = last.Seq
		v.lastHash = last.RecordHash
	}
	return v, nil
}

func (v *Vault) Close() error {
	if v.anchor != nil {
		return v.anchor.Close()
	}
	return nil
}

func (v *Vault) Config() VaultConfig      { return v.config }
func (v *Vault) AnchorBackend() string    { return v.anchor.Backend() }
func (v *Vault) AnchorNote() string       { return v.anchorNote }
func (v *Vault) KernelAppendOnly() bool   { return v.appendOnlyKernel }

func (v *Vault) Status() (uint64, string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.lastSeq, v.lastHash
}

// ComputeRecordHash hashes the canonical unsigned payload of a VaultRecord.
func ComputeRecordHash(rec VaultRecord) (string, error) {
	unsigned := VaultRecord{
		Seq:        rec.Seq,
		Type:       rec.Type,
		RecordedAt: rec.RecordedAt,
		Caller:     rec.Caller,
		Sealed:     rec.Sealed,
		Meta:       rec.Meta,
		PrevHash:   rec.PrevHash,
	}
	canonical, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// Append seals a new VaultRecord into vault.jsonl (O_APPEND + fsync) and
// extends the hardware/file anchor.
func (v *Vault) Append(recType string, caller CallerInfo, sealed *sncrypto.SealedBox, meta map[string]string) (*VaultRecord, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if recType == RecordTypeIncident {
		if sealed == nil {
			return nil, errors.New("INCIDENT record requires a sealed encrypted payload")
		}
		if sealed.KeyID != v.config.ParentKeyID {
			return nil, fmt.Errorf("sealed payload key_id mismatch: got %q, expected %q", sealed.KeyID, v.config.ParentKeyID)
		}
	}

	nextSeq := v.lastSeq + 1
	rec := VaultRecord{
		Seq:        nextSeq,
		Type:       recType,
		RecordedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Caller:     caller,
		Sealed:     sealed,
		Meta:       meta,
		PrevHash:   v.lastHash,
	}
	hashHex, err := ComputeRecordHash(rec)
	if err != nil {
		return nil, err
	}
	rec.RecordHash = hashHex
	sig := ed25519.Sign(v.daemonPriv, []byte(hashHex))
	rec.DaemonSig = base64.StdEncoding.EncodeToString(sig)

	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')

	f, err := os.OpenFile(v.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open vault log: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write vault log: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("sync vault log: %w", err)
	}
	if !v.appendOnlyKernel {
		v.appendOnlyKernel = TryEnableAppendOnly(f)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	if _, err := v.anchor.Extend(nextSeq, hashHex); err != nil {
		return nil, fmt.Errorf("extend tamper anchor: %w", err)
	}

	v.lastSeq = nextSeq
	v.lastHash = hashHex
	return &rec, nil
}

// ReadAllRecords parses every JSON line from vault.jsonl.
func ReadAllRecords(logPath string) ([]VaultRecord, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []VaultRecord
	scanner := bufio.NewScanner(f)
	// Allow up to 8 MB per record (e.g. if future versions include screenshots).
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var rec VaultRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return nil, fmt.Errorf("corrupted JSON at line %d: %w", lineNo, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

// VerifyVaultDir performs full cryptographic verification of vault.jsonl
// against the daemon's Ed25519 public key and the TPM/file anchor.
// Does NOT require the parent's private key.
func VerifyVaultDir(dir string, forceFileAnchor bool) (*VerificationReport, []VaultRecord, error) {
	cfgBytes, err := os.ReadFile(filepath.Join(dir, vaultConfigFileName))
	if err != nil {
		return nil, nil, fmt.Errorf("read vault config: %w", err)
	}
	var cfg VaultConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse vault config: %w", err)
	}
	daemonPubRaw, err := base64.StdEncoding.DecodeString(cfg.DaemonPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode daemon public key: %w", err)
	}
	daemonPub := ed25519.PublicKey(daemonPubRaw)

	records, err := ReadAllRecords(filepath.Join(dir, vaultLogFileName))
	if err != nil {
		return nil, nil, err
	}

	anchor, _ := tpm.OpenAnchor(dir, forceFileAnchor)
	defer anchor.Close()

	rep := &VerificationReport{
		OK:            true,
		AnchorBackend: anchor.Backend(),
		DaemonPubKey:  cfg.DaemonPublicKey,
		ParentKeyID:   cfg.ParentKeyID,
		HeadHash:      GenesisPrevHash,
	}

	expectedPrev := GenesisPrevHash
	cumDigest := hex.EncodeToString(make([]byte, 32))

	for idx, rec := range records {
		expectedSeq := uint64(idx + 1)
		if rec.Seq != expectedSeq {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record %d: sequence gap or reorder (got seq=%d, expected %d)", idx+1, rec.Seq, expectedSeq))
		}
		if rec.PrevHash != expectedPrev {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record seq=%d: broken hash chain (prev_hash mismatch — prior record edited or deleted)", rec.Seq))
		}
		recomputed, err := ComputeRecordHash(rec)
		if err != nil {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record seq=%d: hash computation error: %v", rec.Seq, err))
		} else if recomputed != rec.RecordHash {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record seq=%d: content hash mismatch (record was tampered with)", rec.Seq))
		}

		sigBytes, err := base64.StdEncoding.DecodeString(rec.DaemonSig)
		if err != nil || !ed25519.Verify(daemonPub, []byte(rec.RecordHash), sigBytes) {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record seq=%d: invalid daemon Ed25519 signature (forged or modified record)", rec.Seq))
		}

		nextCum, err := tpm.ExtendDigest(cumDigest, rec.RecordHash)
		if err != nil {
			rep.OK = false
			rep.Errors = append(rep.Errors, fmt.Sprintf("record seq=%d: cumulative digest error: %v", rec.Seq, err))
		} else {
			cumDigest = nextCum
		}

		expectedPrev = rec.RecordHash
		rep.RecordCount++
		rep.HeadHash = rec.RecordHash
		if rec.Type == RecordTypeIncident {
			rep.IncidentCount++
		}
		if rec.Type == RecordTypeTamperGap {
			rep.TamperEventCount++
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("seq=%d at %s: extension heartbeat gap detected (%v)", rec.Seq, rec.RecordedAt, rec.Meta))
		}
	}
	rep.CumulativeDigest = cumDigest

	// Verify against external anchor (catches tail truncation & whole-file replacement).
	anchorState, err := anchor.Read()
	if err != nil {
		rep.OK = false
		rep.AnchorMatched = false
		rep.Errors = append(rep.Errors, fmt.Sprintf("failed to read %s anchor: %v", anchor.Backend(), err))
	} else if anchorState.Count != rep.RecordCount || anchorState.CumulativeDigest != rep.CumulativeDigest {
		rep.OK = false
		rep.AnchorMatched = false
		rep.Errors = append(rep.Errors, fmt.Sprintf(
			"TAIL TRUNCATION OR REPLACEMENT DETECTED: log has %d records (digest %s...) but %s anchor recorded %d records (digest %s...)",
			rep.RecordCount, shortHex(rep.CumulativeDigest), anchor.Backend(), anchorState.Count, shortHex(anchorState.CumulativeDigest),
		))
	} else {
		rep.AnchorMatched = true
	}

	return rep, records, nil
}

func shortHex(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:16]
}
