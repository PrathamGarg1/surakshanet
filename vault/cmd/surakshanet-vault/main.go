package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/PrathamGarg1/surakshanet/vault/internal/chain"
	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
	"github.com/PrathamGarg1/surakshanet/vault/internal/ipc"
	snpdf "github.com/PrathamGarg1/surakshanet/vault/internal/pdf"
)

func defaultVaultDir() string {
	if runtime.GOOS == "windows" {
		return `C:\ProgramData\SurakshaNet\vault`
	}
	return "/var/lib/surakshanet/vault"
}

func defaultSocket() (string, string) {
	if runtime.GOOS == "windows" {
		return "tcp", "127.0.0.1:48921"
	}
	return "unix", "/run/surakshanet/vault.sock"
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "daemon":
		err = cmdDaemon(args)
	case "bridge":
		err = cmdBridge(args)
	case "verify":
		err = cmdVerify(args)
	case "export":
		err = cmdExport(args)
	case "verify-pdf":
		err = cmdVerifyPDF(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`SurakshaNet Tamper-Evident Evidence Vault

Usage:
  surakshanet-vault init        Generate Parent keypair + initialize admin vault
  surakshanet-vault daemon      Run privileged append-only Vault Daemon
  surakshanet-vault bridge      Run Chrome Native Messaging Host bridge (stdio <-> daemon)
  surakshanet-vault verify      Verify hash chain, Ed25519 signatures, and TPM/anchor digest
  surakshanet-vault export      Parent decrypt + verify + export digitally signed PDF & JSON
  surakshanet-vault verify-pdf  Verify cryptographic PKCS#7 signature of an exported PDF`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	vaultDir := fs.String("vault-dir", defaultVaultDir(), "admin-only vault directory")
	parentKeyOut := fs.String("parent-key-out", "./parent.key.json", "output path for encrypted parent private key (move to USB/parent device)")
	parentPubOut := fs.String("parent-pub-out", "./parent.pub.json", "output path for parent public key bundle")
	parentCertOut := fs.String("parent-cert-out", "./parent.crt.pem", "output path for parent PDF verification certificate")
	parentLabel := fs.String("label", "SurakshaNet Parent Guardian", "human-readable parent label embedded in certificate")
	passphrase := fs.String("passphrase", "", "passphrase (>=8 chars) to encrypt parent.key.json (or set SURAKSHANET_PASSPHRASE)")
	noTPM := fs.Bool("no-tpm", false, "force admin file anchor instead of probing TPM 2.0")
	_ = fs.Parse(args)

	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("SURAKSHANET_PASSPHRASE")
	}
	if len(pass) < 8 {
		return errors.New("passphrase must be at least 8 characters (pass --passphrase or set SURAKSHANET_PASSPHRASE)")
	}

	mat, err := sncrypto.GenerateParentKeyMaterial(*parentLabel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*parentKeyOut), 0o700); err != nil {
		return err
	}
	if err := sncrypto.SaveEncryptedKeyFile(*parentKeyOut, mat, pass); err != nil {
		return err
	}

	pubBundle := mat.PublicBundle()
	pubJSON, err := json.MarshalIndent(pubBundle, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*parentPubOut, pubJSON, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(*parentCertOut, []byte(pubBundle.PDFCertPEM), 0o644); err != nil {
		return err
	}

	v, err := chain.InitVault(*vaultDir, pubBundle, *noTPM)
	if err != nil {
		return err
	}
	defer v.Close()

	fmt.Printf("SurakshaNet Vault initialized!\n")
	fmt.Printf("  Vault Dir:        %s\n", *vaultDir)
	fmt.Printf("  Anchor Backend:   %s (%s)\n", v.AnchorBackend(), v.AnchorNote())
	fmt.Printf("  Kernel Append-On: %v\n", v.KernelAppendOnly())
	fmt.Printf("  Parent Key ID:    %s\n", pubBundle.KeyID)
	fmt.Printf("  Parent PublicKey: %s\n", pubBundle.ParentPublicKey)
	fmt.Printf("  Parent Key File:  %s  <-- MOVE THIS TO PARENT'S USB / DEVICE & DELETE FROM CHILD PC!\n", *parentKeyOut)
	fmt.Printf("  Parent Pub File:  %s\n", *parentPubOut)
	fmt.Printf("  Parent Cert File: %s\n", *parentCertOut)
	return nil
}

func cmdDaemon(args []string) error {
	defNet, defAddr := defaultSocket()
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	vaultDir := fs.String("vault-dir", defaultVaultDir(), "admin-only vault directory")
	network := fs.String("network", defNet, "IPC network (unix or tcp)")
	address := fs.String("addr", defAddr, "IPC socket path or loopback host:port")
	heartbeatTimeout := fs.Duration("heartbeat-timeout", 5*time.Minute, "log TAMPER_HEARTBEAT_GAP if extension stops heartbeating (0 to disable)")
	noTPM := fs.Bool("no-tpm", false, "disable TPM 2.0 probing")
	_ = fs.Parse(args)

	v, err := chain.OpenVault(*vaultDir, *noTPM)
	if err != nil {
		return err
	}
	defer v.Close()

	log.Printf("[surakshanet-vault] starting privileged daemon dir=%s listen=%s://%s anchor=%s (%s)",
		*vaultDir, *network, *address, v.AnchorBackend(), v.AnchorNote())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := ipc.NewServer(v, *network, *address, *heartbeatTimeout)
	return srv.Serve(ctx)
}

func cmdBridge(args []string) error {
	defNet, defAddr := defaultSocket()
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	network := fs.String("network", defNet, "daemon IPC network")
	address := fs.String("addr", defAddr, "daemon IPC address")
	_ = fs.Parse(args)

	// Chrome passes the calling extension origin as a positional arg on Windows/Linux; ignore it safely.
	return ipc.RunNativeBridge(os.Stdin, os.Stdout, *network, *address)
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	vaultDir := fs.String("vault-dir", defaultVaultDir(), "vault directory to verify")
	noTPM := fs.Bool("no-tpm", false, "verify against admin file anchor instead of TPM 2.0")
	asJSON := fs.Bool("json", false, "output JSON report")
	_ = fs.Parse(args)

	rep, _, err := chain.VerifyVaultDir(*vaultDir, *noTPM)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	} else {
		status := "VERIFIED (INTACT)"
		if !rep.OK {
			status = "TAMPERING DETECTED"
		}
		fmt.Printf("Status:            %s\n", status)
		fmt.Printf("Anchor Backend:    %s (matched=%v)\n", rep.AnchorBackend, rep.AnchorMatched)
		fmt.Printf("Parent Key ID:     %s\n", rep.ParentKeyID)
		fmt.Printf("Records Checked:   %d (incidents=%d, tamper_alerts=%d)\n", rep.RecordCount, rep.IncidentCount, rep.TamperEventCount)
		fmt.Printf("Head Hash:         %s\n", rep.HeadHash)
		fmt.Printf("Cumulative Digest: %s\n", rep.CumulativeDigest)
		for _, w := range rep.Warnings {
			fmt.Printf("  [WARNING] %s\n", w)
		}
		for _, e := range rep.Errors {
			fmt.Printf("  [ERROR]   %s\n", e)
		}
	}

	if !rep.OK {
		return errors.New("vault integrity verification FAILED")
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	vaultDir := fs.String("vault-dir", defaultVaultDir(), "vault directory")
	parentKeyPath := fs.String("parent-key", "./parent.key.json", "path to encrypted parent.key.json")
	passphrase := fs.String("passphrase", "", "passphrase for parent.key.json (or SURAKSHANET_PASSPHRASE)")
	pdfOut := fs.String("pdf-out", "./surakshanet-verified-report.pdf", "output path for digitally signed PDF")
	jsonOut := fs.String("json-out", "", "optional output path for verified decrypted JSON bundle")
	noTPM := fs.Bool("no-tpm", false, "verify against admin file anchor instead of TPM 2.0")
	allowTampered := fs.Bool("allow-tampered", false, "still generate report (clearly stamped TAMPERING DETECTED) if vault failed verification")
	_ = fs.Parse(args)

	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("SURAKSHANET_PASSPHRASE")
	}
	if pass == "" {
		return errors.New("passphrase required (--passphrase or SURAKSHANET_PASSPHRASE)")
	}

	mat, err := sncrypto.LoadEncryptedKeyFile(*parentKeyPath, pass)
	if err != nil {
		return err
	}

	rep, records, err := chain.VerifyVaultDir(*vaultDir, *noTPM)
	if err != nil {
		return err
	}
	if !rep.OK && !*allowTampered {
		return fmt.Errorf("refusing to export tampered vault without --allow-tampered (%d errors: %v)", len(rep.Errors), rep.Errors)
	}

	var incidents []snpdf.DecryptedIncident
	for _, rec := range records {
		if rec.Type != chain.RecordTypeIncident || rec.Sealed == nil {
			continue
		}
		plain, err := sncrypto.Open(rec.Sealed, mat.ECDHPrivate)
		if err != nil {
			return fmt.Errorf("decrypt record seq=%d: %w", rec.Seq, err)
		}
		var payload struct {
			ID       string  `json:"id"`
			TS       string  `json:"ts"`
			Contact  string  `json:"contact"`
			Severity string  `json:"severity"`
			Score    float64 `json:"score"`
			Text     string  `json:"text"`
		}
		if err := json.Unmarshal(plain, &payload); err != nil {
			return fmt.Errorf("parse decrypted payload seq=%d: %w", rec.Seq, err)
		}
		incidents = append(incidents, snpdf.DecryptedIncident{
			Seq:        rec.Seq,
			RecordedAt: rec.RecordedAt,
			RecordHash: rec.RecordHash,
			Contact:    payload.Contact,
			Severity:   payload.Severity,
			Score:      payload.Score,
			Text:       payload.Text,
			CapturedAt: payload.TS,
			ID:         payload.ID,
		})
	}

	pdfBytes, err := snpdf.GenerateSignedReport(rep, incidents, mat.PDFCert, mat.PDFSignPrivate)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*pdfOut, pdfBytes, 0o600); err != nil {
		return err
	}

	if *jsonOut != "" {
		bundle := map[string]any{
			"exported_at":  time.Now().UTC().Format(time.RFC3339),
			"verification": rep,
			"incidents":    incidents,
		}
		b, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*jsonOut, b, 0o600); err != nil {
			return err
		}
	}

	fmt.Printf("Exported digitally signed evidence report!\n")
	fmt.Printf("  Integrity:        OK=%v (anchor=%s, matched=%v)\n", rep.OK, rep.AnchorBackend, rep.AnchorMatched)
	fmt.Printf("  Incidents:        %d\n", len(incidents))
	fmt.Printf("  Signed PDF:       %s (%d bytes)\n", *pdfOut, len(pdfBytes))
	if *jsonOut != "" {
		fmt.Printf("  Verified JSON:    %s\n", *jsonOut)
	}
	return nil
}

func cmdVerifyPDF(args []string) error {
	fs := flag.NewFlagSet("verify-pdf", flag.ExitOnError)
	pdfPath := fs.String("pdf", "", "path to signed PDF report")
	certPath := fs.String("cert", "", "path to parent.crt.pem (recommended)")
	_ = fs.Parse(args)

	if *pdfPath == "" {
		return errors.New("--pdf path is required")
	}
	pdfBytes, err := os.ReadFile(*pdfPath)
	if err != nil {
		return err
	}
	certPEM := ""
	if *certPath != "" {
		c, err := os.ReadFile(*certPath)
		if err != nil {
			return err
		}
		certPEM = string(c)
	}

	res, err := snpdf.VerifySignedPDF(pdfBytes, certPEM)
	if err != nil {
		return err
	}
	fmt.Printf("PDF SIGNATURE VERIFIED!\n")
	fmt.Printf("  Signer:       %s\n", res.SignerSubject)
	fmt.Printf("  Signed Bytes: %d / %d\n", res.SignedBytes, res.TotalBytes)
	fmt.Printf("  ByteRange:    %v\n", res.ByteRange)
	return nil
}
