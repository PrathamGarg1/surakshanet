package tpm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	BackendTPM2Hardware = "TPM2_HARDWARE"
	BackendAdminFile    = "ADMIN_FILE_ANCHOR"

	// DefaultNVDigestIndex stores [uint64 seq || 32-byte cumulative SHA-256].
	DefaultNVDigestIndex tpm2.TPMHandle = 0x01500042
	// DefaultNVCounterIndex is a hardware-enforced monotonic counter.
	DefaultNVCounterIndex tpm2.TPMHandle = 0x01500043
)

// AnchorState represents the tamper-evident root state used to detect tail
// truncation and offline disk edits.
type AnchorState struct {
	Backend          string `json:"backend"`
	Count            uint64 `json:"count"`
	CumulativeDigest string `json:"cumulative_digest"`
	HeadHash         string `json:"head_hash"`
	UpdatedAt        string `json:"updated_at"`
}

// Anchor records every appended vault entry into either a hardware TPM 2.0
// NVRAM index or an admin-only anchor file fallback.
type Anchor interface {
	Backend() string
	Extend(seq uint64, recordHashHex string) (*AnchorState, error)
	Read() (*AnchorState, error)
	Close() error
}

// ExtendDigest computes C_i = SHA-256(C_{i-1} || H_i), matching TPM NV/PCR extend semantics.
func ExtendDigest(prevDigestHex string, recordHashHex string) (string, error) {
	var prev []byte
	if prevDigestHex == "" {
		prev = make([]byte, 32)
	} else {
		var err error
		prev, err = hex.DecodeString(prevDigestHex)
		if err != nil || len(prev) != 32 {
			return "", errors.New("invalid previous cumulative digest")
		}
	}
	rec, err := hex.DecodeString(recordHashHex)
	if err != nil || len(rec) != 32 {
		return "", errors.New("invalid record hash hex")
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(rec)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// OpenAnchor tries to open a real TPM 2.0 hardware anchor first (unless
// forceFileFallback is true). If no TPM 2.0 device is available, it falls back
// to an admin-only FileAnchor and reports BackendAdminFile honestly.
func OpenAnchor(vaultDir string, forceFileFallback bool) (Anchor, string) {
	if !forceFileFallback {
		if tpmAnchor, err := OpenTPM2Anchor(DefaultNVDigestIndex, DefaultNVCounterIndex); err == nil {
			return tpmAnchor, "TPM 2.0 hardware anchor active"
		} else {
			fa := NewFileAnchor(filepath.Join(vaultDir, "anchor.json"))
			return fa, fmt.Sprintf("TPM 2.0 unavailable (%v); using admin-only file anchor", err)
		}
	}
	return NewFileAnchor(filepath.Join(vaultDir, "anchor.json")), "using admin-only file anchor"
}

// FileAnchor is an admin-only software anchor used when no TPM 2.0 chip is accessible.
type FileAnchor struct {
	mu   sync.Mutex
	path string
}

func NewFileAnchor(path string) *FileAnchor {
	return &FileAnchor{path: path}
}

func (f *FileAnchor) Backend() string { return BackendAdminFile }
func (f *FileAnchor) Close() error    { return nil }

func (f *FileAnchor) Read() (*AnchorState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readLocked()
}

func (f *FileAnchor) readLocked() (*AnchorState, error) {
	raw, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return &AnchorState{
			Backend:          BackendAdminFile,
			Count:            0,
			CumulativeDigest: hex.EncodeToString(make([]byte, 32)),
			HeadHash:         hex.EncodeToString(make([]byte, 32)),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	var st AnchorState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse anchor file: %w", err)
	}
	st.Backend = BackendAdminFile
	return &st, nil
}

func (f *FileAnchor) Extend(seq uint64, recordHashHex string) (*AnchorState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	st, err := f.readLocked()
	if err != nil {
		return nil, err
	}
	if seq != st.Count+1 {
		return nil, fmt.Errorf("anchor sequence mismatch: expected %d, got %d", st.Count+1, seq)
	}
	nextDigest, err := ExtendDigest(st.CumulativeDigest, recordHashHex)
	if err != nil {
		return nil, err
	}
	next := &AnchorState{
		Backend:          BackendAdminFile,
		Count:            seq,
		CumulativeDigest: nextDigest,
		HeadHash:         recordHashHex,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return nil, err
	}
	return next, nil
}

// TPM2Anchor backs the vault chain with two persistent TPM 2.0 NV indices:
//   - a hardware monotonic counter (TPMNTCounter) incremented on every append
//   - a 40-byte digest index holding [uint64 seq || 32-byte cumulative SHA-256]
type TPM2Anchor struct {
	mu           sync.Mutex
	tpm          transport.TPMCloser
	digestIndex  tpm2.TPMHandle
	counterIndex tpm2.TPMHandle
	digestName   tpm2.TPM2BName
	counterName  tpm2.TPM2BName
}

func OpenTPM2Anchor(digestIndex, counterIndex tpm2.TPMHandle) (*TPM2Anchor, error) {
	rwc, err := transport.OpenTPM()
	if err != nil {
		return nil, err
	}
	a := &TPM2Anchor{
		tpm:          rwc,
		digestIndex:  digestIndex,
		counterIndex: counterIndex,
	}
	if err := a.ensureIndices(); err != nil {
		_ = rwc.Close()
		return nil, err
	}
	return a, nil
}

func (a *TPM2Anchor) Backend() string { return BackendTPM2Hardware }
func (a *TPM2Anchor) Close() error    { return a.tpm.Close() }

func (a *TPM2Anchor) ensureIndices() error {
	// Ensure 40-byte digest index exists.
	pubResp, err := tpm2.NVReadPublic{NVIndex: a.digestIndex}.Execute(a.tpm)
	if err != nil {
		_, defErr := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex: a.digestIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					NT:         tpm2.TPMNTOrdinary,
				},
				DataSize: 40,
			}),
		}.Execute(a.tpm)
		if defErr != nil {
			return fmt.Errorf("define TPM NV digest index 0x%x: %w", a.digestIndex, defErr)
		}
		pubResp, err = tpm2.NVReadPublic{NVIndex: a.digestIndex}.Execute(a.tpm)
		if err != nil {
			return fmt.Errorf("read TPM NV digest public: %w", err)
		}
	}
	a.digestName = pubResp.NVName

	// Ensure hardware monotonic counter index exists.
	cntResp, err := tpm2.NVReadPublic{NVIndex: a.counterIndex}.Execute(a.tpm)
	if err != nil {
		_, defErr := tpm2.NVDefineSpace{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex: a.counterIndex,
				NameAlg: tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{
					OwnerWrite: true,
					OwnerRead:  true,
					NT:         tpm2.TPMNTCounter,
				},
				DataSize: 8,
			}),
		}.Execute(a.tpm)
		if defErr != nil {
			return fmt.Errorf("define TPM NV counter index 0x%x: %w", a.counterIndex, defErr)
		}
		cntResp, err = tpm2.NVReadPublic{NVIndex: a.counterIndex}.Execute(a.tpm)
		if err != nil {
			return fmt.Errorf("read TPM NV counter public: %w", err)
		}
	}
	a.counterName = cntResp.NVName
	return nil
}

func (a *TPM2Anchor) Read() (*AnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.readLocked()
}

func (a *TPM2Anchor) readLocked() (*AnchorState, error) {
	pubResp, err := tpm2.NVReadPublic{NVIndex: a.digestIndex}.Execute(a.tpm)
	if err != nil {
		return nil, err
	}
	pubContents, err := pubResp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	if !pubContents.Attributes.Written {
		return &AnchorState{
			Backend:          BackendTPM2Hardware,
			Count:            0,
			CumulativeDigest: hex.EncodeToString(make([]byte, 32)),
			HeadHash:         hex.EncodeToString(make([]byte, 32)),
		}, nil
	}

	readResp, err := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: a.digestIndex,
			Name:   a.digestName,
		},
		Size:   40,
		Offset: 0,
	}.Execute(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM NVRead digest: %w", err)
	}
	buf := readResp.Data.Buffer
	if len(buf) != 40 {
		return nil, fmt.Errorf("unexpected TPM NV digest length: %d", len(buf))
	}
	seq := binary.BigEndian.Uint64(buf[:8])
	digestHex := hex.EncodeToString(buf[8:40])
	return &AnchorState{
		Backend:          BackendTPM2Hardware,
		Count:            seq,
		CumulativeDigest: digestHex,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (a *TPM2Anchor) Extend(seq uint64, recordHashHex string) (*AnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	cur, err := a.readLocked()
	if err != nil {
		return nil, err
	}
	if seq != cur.Count+1 {
		return nil, fmt.Errorf("TPM anchor sequence mismatch: expected %d, got %d", cur.Count+1, seq)
	}
	nextDigestHex, err := ExtendDigest(cur.CumulativeDigest, recordHashHex)
	if err != nil {
		return nil, err
	}
	nextDigestBytes, err := hex.DecodeString(nextDigestHex)
	if err != nil {
		return nil, err
	}

	// 1. Increment hardware monotonic counter (irreversible in TPM silicon).
	if _, err := (tpm2.NVIncrement{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: a.counterIndex,
			Name:   a.counterName,
		},
	}).Execute(a.tpm); err != nil {
		return nil, fmt.Errorf("TPM NVIncrement: %w", err)
	}

	// 2. Persist [seq || cumulativeDigest] into TPM NV index.
	payload := make([]byte, 40)
	binary.BigEndian.PutUint64(payload[:8], seq)
	copy(payload[8:40], nextDigestBytes)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NVIndex: tpm2.NamedHandle{
			Handle: a.digestIndex,
			Name:   a.digestName,
		},
		Data:   tpm2.TPM2BMaxNVBuffer{Buffer: payload},
		Offset: 0,
	}).Execute(a.tpm); err != nil {
		return nil, fmt.Errorf("TPM NVWrite: %w", err)
	}

	return &AnchorState{
		Backend:          BackendTPM2Hardware,
		Count:            seq,
		CumulativeDigest: nextDigestHex,
		HeadHash:         recordHashHex,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}
