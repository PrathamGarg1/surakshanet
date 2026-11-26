package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PrathamGarg1/surakshanet/vault/internal/chain"
	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
)

const (
	ActionAppendIncident = "APPEND_INCIDENT"
	ActionHeartbeat      = "HEARTBEAT"
	ActionStatus         = "STATUS"
)

// Request is the write-only RPC schema accepted by the privileged vault daemon.
// By design, there are NO read, list, clear, or delete actions exposed over IPC.
type Request struct {
	Action      string              `json:"action"`
	ExtensionID string              `json:"ext_id,omitempty"`
	Sealed      *sncrypto.SealedBox `json:"sealed,omitempty"`
	Meta        map[string]string   `json:"meta,omitempty"`
}

// Response is returned to the Chrome Native Messaging bridge.
type Response struct {
	OK               bool   `json:"ok"`
	Error            string `json:"error,omitempty"`
	Seq              uint64 `json:"seq,omitempty"`
	RecordHash       string `json:"record_hash,omitempty"`
	AnchorBackend    string `json:"anchor_backend,omitempty"`
	ParentKeyID      string `json:"parent_key_id,omitempty"`
	KernelAppendOnly bool   `json:"kernel_append_only,omitempty"`
}

// Server serves write-only IPC requests over a local Unix socket (or TCP loopback on Windows)
// and monitors extension heartbeats to detect kill/tamper attempts.
type Server struct {
	vault            *chain.Vault
	network          string
	address          string
	heartbeatTimeout time.Duration

	mu               sync.Mutex
	lastHeartbeat    time.Time
	heartbeatSeen    bool
	gapLoggedForIdle bool
}

func NewServer(vault *chain.Vault, network, address string, heartbeatTimeout time.Duration) *Server {
	return &Server{
		vault:            vault,
		network:          network,
		address:          address,
		heartbeatTimeout: heartbeatTimeout,
	}
}

func (s *Server) Serve(ctx context.Context) error {
	if s.network == "unix" {
		if err := os.MkdirAll(filepath.Dir(s.address), 0o755); err != nil {
			return fmt.Errorf("create socket dir: %w", err)
		}
		_ = os.Remove(s.address)
	}

	ln, err := net.Listen(s.network, s.address)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", s.network, s.address, err)
	}
	if s.network == "unix" {
		// Socket is write-only RPC (no read/delete actions), so standard users can append.
		_ = os.Chmod(s.address, 0o666)
	}

	_, _ = s.vault.Append(chain.RecordTypeDaemonStart, chain.CallerInfo{
		UID: os.Getuid(),
		PID: os.Getpid(),
	}, nil, map[string]string{
		"anchor_backend": s.vault.AnchorBackend(),
	})

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if s.heartbeatTimeout > 0 {
		go s.watchdogLoop(ctx)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("[vault-daemon] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) watchdogLoop(ctx context.Context) {
	ticker := time.NewTicker(s.heartbeatTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			seen := s.heartbeatSeen
			last := s.lastHeartbeat
			logged := s.gapLoggedForIdle
			if seen && !logged && now.Sub(last) > s.heartbeatTimeout {
				s.gapLoggedForIdle = true
				s.mu.Unlock()
				gapSec := int(now.Sub(last).Seconds())
				_, _ = s.vault.Append(chain.RecordTypeTamperGap, chain.CallerInfo{
					UID: os.Getuid(),
					PID: os.Getpid(),
				}, nil, map[string]string{
					"last_heartbeat": last.UTC().Format(time.RFC3339),
					"gap_seconds":    fmt.Sprintf("%d", gapSec),
					"reason":         "extension stopped sending heartbeats",
				})
			} else {
				s.mu.Unlock()
			}
		}
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	uid, pid := PeerCredentials(conn)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	enc := json.NewEncoder(conn)

	for scanner.Scan() {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = enc.Encode(Response{OK: false, Error: "malformed JSON request"})
			return
		}
		resp := s.dispatch(req, chain.CallerInfo{
			UID:         uid,
			PID:         pid,
			ExtensionID: req.ExtensionID,
		})
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(req Request, caller chain.CallerInfo) Response {
	switch req.Action {
	case ActionAppendIncident:
		if req.Sealed == nil {
			return Response{OK: false, Error: "sealed payload is required"}
		}
		rec, err := s.vault.Append(chain.RecordTypeIncident, caller, req.Sealed, req.Meta)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK:               true,
			Seq:              rec.Seq,
			RecordHash:       rec.RecordHash,
			AnchorBackend:    s.vault.AnchorBackend(),
			ParentKeyID:      s.vault.Config().ParentKeyID,
			KernelAppendOnly: s.vault.KernelAppendOnly(),
		}

	case ActionHeartbeat:
		s.mu.Lock()
		s.lastHeartbeat = time.Now().UTC()
		s.heartbeatSeen = true
		s.gapLoggedForIdle = false
		s.mu.Unlock()

		rec, err := s.vault.Append(chain.RecordTypeHeartbeat, caller, nil, req.Meta)
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{
			OK:               true,
			Seq:              rec.Seq,
			RecordHash:       rec.RecordHash,
			AnchorBackend:    s.vault.AnchorBackend(),
			ParentKeyID:      s.vault.Config().ParentKeyID,
			KernelAppendOnly: s.vault.KernelAppendOnly(),
		}

	case ActionStatus:
		seq, hash := s.vault.Status()
		return Response{
			OK:               true,
			Seq:              seq,
			RecordHash:       hash,
			AnchorBackend:    s.vault.AnchorBackend(),
			ParentKeyID:      s.vault.Config().ParentKeyID,
			KernelAppendOnly: s.vault.KernelAppendOnly(),
		}

	default:
		return Response{OK: false, Error: fmt.Sprintf("unsupported or forbidden action %q (vault IPC is strictly append-only)", req.Action)}
	}
}

// SendRequest sends a single JSON-line request to the vault daemon and reads its reply.
func SendRequest(network, address string, req Request) (*Response, error) {
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect vault daemon (%s %s): %w", network, address, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("vault daemon closed connection without response")
	}
	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse daemon response: %w", err)
	}
	return &resp, nil
}
