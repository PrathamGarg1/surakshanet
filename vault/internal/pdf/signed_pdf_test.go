package pdf

import (
	"bytes"
	"testing"

	"github.com/PrathamGarg1/surakshanet/vault/internal/chain"
	sncrypto "github.com/PrathamGarg1/surakshanet/vault/internal/crypto"
)

func TestSignedPDFGenerateVerifyAndTamperRejection(t *testing.T) {
	mat, err := sncrypto.GenerateParentKeyMaterial("Parent Guardian")
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	other, err := sncrypto.GenerateParentKeyMaterial("Other Guardian")
	if err != nil {
		t.Fatalf("keygen other: %v", err)
	}

	rep := &chain.VerificationReport{
		OK:               true,
		RecordCount:      3,
		IncidentCount:    1,
		HeadHash:         "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		CumulativeDigest: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		AnchorBackend:    "ADMIN_FILE_ANCHOR",
		AnchorMatched:    true,
		ParentKeyID:      mat.KeyID,
	}
	incidents := []DecryptedIncident{
		{
			Seq:        2,
			RecordedAt: "2026-11-26T13:30:00Z",
			RecordHash: rep.HeadHash,
			Contact:    "Unknown Predator",
			Severity:   "high",
			Score:      0.96,
			Text:       "Don't tell your parents about our secret chat",
		},
	}

	pdfBytes, err := GenerateSignedReport(rep, incidents, mat.PDFCert, mat.PDFSignPrivate)
	if err != nil {
		t.Fatalf("GenerateSignedReport: %v", err)
	}

	res, err := VerifySignedPDF(pdfBytes, mat.PDFCertPEM)
	if err != nil {
		t.Fatalf("VerifySignedPDF failed on intact PDF: %v", err)
	}
	if !res.Valid {
		t.Fatal("expected valid signature result")
	}

	// Wrong certificate must fail verification.
	if _, err := VerifySignedPDF(pdfBytes, other.PDFCertPEM); err == nil {
		t.Fatal("expected VerifySignedPDF to fail against wrong parent certificate")
	}

	// Tampering 1 byte of the PDF message text must invalidate signature.
	tampered := bytes.Replace(pdfBytes, []byte("secret chat"), []byte("normal chat"), 1)
	if bytes.Equal(tampered, pdfBytes) {
		t.Fatal("test setup failed to find target text in PDF")
	}
	if _, err := VerifySignedPDF(tampered, mat.PDFCertPEM); err == nil {
		t.Fatal("expected VerifySignedPDF to FAIL after 1-word edit in PDF")
	}

	// Appending trailing bytes after %%EOF must fail ByteRange coverage check.
	appended := append(append([]byte(nil), pdfBytes...), []byte("\n% appended garbage\n")...)
	if _, err := VerifySignedPDF(appended, mat.PDFCertPEM); err == nil {
		t.Fatal("expected VerifySignedPDF to FAIL when trailing bytes are appended")
	}
}
