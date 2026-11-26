package pdf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PrathamGarg1/surakshanet/vault/internal/chain"
	"github.com/digitorus/pkcs7"
)

const sigHexCapacity = 16384 // 8192 bytes of DER PKCS#7 signature space

// DecryptedIncident is a verified, decrypted incident record ready for reporting.
type DecryptedIncident struct {
	Seq        uint64  `json:"seq"`
	RecordedAt string  `json:"recorded_at"`
	RecordHash string  `json:"record_hash"`
	Contact    string  `json:"contact"`
	Severity   string  `json:"severity"`
	Score      float64 `json:"score"`
	Text       string  `json:"text"`
	CapturedAt string  `json:"ts"`
	ID         string  `json:"id"`
}

// PDFVerificationResult describes the outcome of verifying a signed SurakshaNet PDF.
type PDFVerificationResult struct {
	Valid         bool      `json:"valid"`
	SignerSubject string    `json:"signer_subject"`
	SignedBytes   int       `json:"signed_bytes"`
	TotalBytes    int       `json:"total_bytes"`
	ByteRange     [4]int    `json:"byte_range"`
	VerifiedAt    time.Time `json:"verified_at"`
}

// GenerateSignedReport builds a valid multi-page PDF 1.4 evidence report and
// embeds a standard ISO 32000-1 /adbe.pkcs7.detached cryptographic signature.
func GenerateSignedReport(
	report *chain.VerificationReport,
	incidents []DecryptedIncident,
	cert *x509.Certificate,
	privKey *ecdsa.PrivateKey,
) ([]byte, error) {
	if cert == nil || privKey == nil {
		return nil, errors.New("certificate and private key are required to sign PDF")
	}

	lines := buildReportLines(report, incidents)
	pages := paginateLines(lines, 56)
	rawPDF, byteRangeOffset, contentsHexOffset, err := assemblePDFWithSignaturePlaceholder(pages, cert.Subject.CommonName)
	if err != nil {
		return nil, err
	}

	// Contents token starts at '<' (contentsHexOffset-1) and ends after '>' (contentsHexOffset+sigHexCapacity+1).
	contentsStart := contentsHexOffset - 1
	contentsEnd := contentsHexOffset + sigHexCapacity + 1
	totalLen := len(rawPDF)

	brFormatted := fmt.Sprintf("[%010d %010d %010d %010d]", 0, contentsStart, contentsEnd, totalLen-contentsEnd)
	if len(brFormatted) != len("[0000000000 0000000000 0000000000 0000000000]") {
		return nil, errors.New("internal ByteRange formatting length mismatch")
	}
	copy(rawPDF[byteRangeOffset:byteRangeOffset+len(brFormatted)], []byte(brFormatted))

	signedDataBuf := make([]byte, 0, contentsStart+(totalLen-contentsEnd))
	signedDataBuf = append(signedDataBuf, rawPDF[:contentsStart]...)
	signedDataBuf = append(signedDataBuf, rawPDF[contentsEnd:]...)

	sd, err := pkcs7.NewSignedData(signedDataBuf)
	if err != nil {
		return nil, fmt.Errorf("init pkcs7 signed data: %w", err)
	}
	sd.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err := sd.AddSigner(cert, privKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("add pkcs7 signer: %w", err)
	}
	sd.Detach()
	derSig, err := sd.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish pkcs7 signature: %w", err)
	}

	hexSig := strings.ToUpper(hex.EncodeToString(derSig))
	if len(hexSig) > sigHexCapacity {
		return nil, fmt.Errorf("PKCS#7 signature (%d hex chars) exceeds placeholder capacity (%d)", len(hexSig), sigHexCapacity)
	}
	copy(rawPDF[contentsHexOffset:contentsHexOffset+len(hexSig)], []byte(hexSig))
	return rawPDF, nil
}

var byteRangeRe = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

// VerifySignedPDF verifies that the PDF's embedded /adbe.pkcs7.detached signature
// matches the exact file bytes covered by /ByteRange and chains to trustedCertPEM.
func VerifySignedPDF(pdfBytes []byte, trustedCertPEM string) (*PDFVerificationResult, error) {
	m := byteRangeRe.FindSubmatch(pdfBytes)
	if m == nil {
		return nil, errors.New("no PDF /ByteRange signature dictionary found")
	}
	var br [4]int
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(string(m[i+1]))
		if err != nil {
			return nil, fmt.Errorf("invalid ByteRange integer: %w", err)
		}
		br[i] = v
	}
	if br[0] != 0 || br[1] <= 0 || br[2] <= br[1] || br[2]+br[3] != len(pdfBytes) {
		return nil, fmt.Errorf("PDF ByteRange does not cover entire file (br=%v total=%d) — possible trailing tampering", br, len(pdfBytes))
	}

	contentsSlice := pdfBytes[br[1]:br[2]]
	if len(contentsSlice) < 4 || contentsSlice[0] != '<' || contentsSlice[len(contentsSlice)-1] != '>' {
		return nil, errors.New("malformed PDF /Contents hex signature block")
	}
	hexBody := strings.TrimSpace(string(contentsSlice[1 : len(contentsSlice)-1]))
	derRaw, err := hex.DecodeString(hexBody)
	if err != nil {
		return nil, fmt.Errorf("decode signature hex: %w", err)
	}
	// Strip trailing zero padding from the fixed-width signature placeholder.
	derTrimmed := trimASN1Padding(derRaw)

	p7, err := pkcs7.Parse(derTrimmed)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#7 signature: %w", err)
	}

	signedBytes := make([]byte, 0, br[1]+br[3])
	signedBytes = append(signedBytes, pdfBytes[br[0]:br[0]+br[1]]...)
	signedBytes = append(signedBytes, pdfBytes[br[2]:br[2]+br[3]]...)
	p7.Content = signedBytes

	if trustedCertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(trustedCertPEM)) {
			return nil, errors.New("failed to parse trusted parent certificate PEM")
		}
		if err := p7.VerifyWithChain(pool); err != nil {
			return nil, fmt.Errorf("PDF signature verification FAILED against parent certificate: %w", err)
		}
	} else {
		if err := p7.Verify(); err != nil {
			return nil, fmt.Errorf("PDF signature verification FAILED: %w", err)
		}
	}

	subject := ""
	if signer := p7.GetOnlySigner(); signer != nil {
		subject = signer.Subject.CommonName
	}
	return &PDFVerificationResult{
		Valid:         true,
		SignerSubject: subject,
		SignedBytes:   len(signedBytes),
		TotalBytes:    len(pdfBytes),
		ByteRange:     br,
		VerifiedAt:    time.Now().UTC(),
	}, nil
}

// LoadCertPEM parses a single X.509 PEM certificate.
func LoadCertPEM(certPEM string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		return nil, errors.New("invalid certificate PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func trimASN1Padding(der []byte) []byte {
	// DER SEQUENCE starts with 0x30 followed by definite length encoding.
	if len(der) < 4 || der[0] != 0x30 {
		return bytes.TrimRight(der, "\x00")
	}
	lenByte := der[1]
	var totalLen int
	if lenByte&0x80 == 0 {
		totalLen = 2 + int(lenByte)
	} else {
		numBytes := int(lenByte & 0x7f)
		if numBytes == 0 || numBytes > 4 || 2+numBytes > len(der) {
			return bytes.TrimRight(der, "\x00")
		}
		bodyLen := 0
		for i := 0; i < numBytes; i++ {
			bodyLen = (bodyLen << 8) | int(der[2+i])
		}
		totalLen = 2 + numBytes + bodyLen
	}
	if totalLen > 0 && totalLen <= len(der) {
		return der[:totalLen]
	}
	return bytes.TrimRight(der, "\x00")
}

func buildReportLines(report *chain.VerificationReport, incidents []DecryptedIncident) []string {
	status := "VERIFIED (INTACT)"
	if !report.OK {
		status = "TAMPERING DETECTED"
	}
	lines := []string{
		"SURAKSHANET - CRYPTOGRAPHICALLY SIGNED EVIDENCE REPORT",
		strings.Repeat("=", 76),
		fmt.Sprintf("Generated (UTC):    %s", time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf("Vault Integrity:    %s", status),
		fmt.Sprintf("Anchor Backend:     %s (Matched: %v)", report.AnchorBackend, report.AnchorMatched),
		fmt.Sprintf("Parent Key ID:      %s", report.ParentKeyID),
		fmt.Sprintf("Records Verified:   %d total | %d incidents | %d tamper alerts", report.RecordCount, report.IncidentCount, report.TamperEventCount),
		fmt.Sprintf("Chain Head SHA256:  %s", report.HeadHash),
		fmt.Sprintf("Cumulative Digest:  %s", report.CumulativeDigest),
		strings.Repeat("-", 76),
	}

	if len(report.Errors) > 0 {
		lines = append(lines, "INTEGRITY ERRORS:")
		for _, e := range report.Errors {
			lines = append(lines, wrapText("  ! "+e, 86)...)
		}
		lines = append(lines, strings.Repeat("-", 76))
	}
	if len(report.Warnings) > 0 {
		lines = append(lines, "TAMPER / HEARTBEAT WARNINGS:")
		for _, w := range report.Warnings {
			lines = append(lines, wrapText("  * "+w, 86)...)
		}
		lines = append(lines, strings.Repeat("-", 76))
	}

	if len(incidents) == 0 {
		lines = append(lines, "No decrypted abusive incidents found in vault.")
		return lines
	}

	for idx, inc := range incidents {
		lines = append(lines,
			fmt.Sprintf("INCIDENT #%d  [Seq %d | Severity: %s | Confidence: %.0f%%]",
				idx+1, inc.Seq, strings.ToUpper(inc.Severity), inc.Score*100),
			fmt.Sprintf("  Vault Timestamp: %s", inc.RecordedAt),
			fmt.Sprintf("  Contact / Chat:  %s", sanitizePDFAscii(inc.Contact)),
			fmt.Sprintf("  Record SHA-256:  %s", inc.RecordHash),
			"  Message:",
		)
		for _, ml := range wrapText(sanitizePDFAscii(inc.Text), 82) {
			lines = append(lines, "    "+ml)
		}
		lines = append(lines, strings.Repeat("-", 76))
	}
	return lines
}

func sanitizePDFAscii(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r >= 32 && r <= 126:
			b.WriteRune(r)
		default:
			// Preserve non-ASCII (e.g. Devanagari) deterministically as Unicode escapes in Type1 PDF stream.
			fmt.Fprintf(&b, "\\u%04X", r)
		}
	}
	return b.String()
}

func escapePDFLiteral(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `(`, `\(`, `)`, `\)`)
	return r.Replace(s)
}

func wrapText(s string, width int) []string {
	if len(s) <= width {
		return []string{s}
	}
	var out []string
	for len(s) > width {
		cut := width
		if sp := strings.LastIndexByte(s[:width], ' '); sp > width/3 {
			cut = sp
		}
		out = append(out, strings.TrimSpace(s[:cut]))
		s = strings.TrimSpace(s[cut:])
	}
	if s != "" {
		out = append(out, s)
	}
	return out
}

func paginateLines(lines []string, perPage int) [][]string {
	if len(lines) == 0 {
		return [][]string{{""}}
	}
	var pages [][]string
	for i := 0; i < len(lines); i += perPage {
		end := i + perPage
		if end > len(lines) {
			end = len(lines)
		}
		pages = append(pages, lines[i:end])
	}
	return pages
}

// assemblePDFWithSignaturePlaceholder builds a deterministic PDF 1.4 with:
//   1: Catalog (/AcroForm -> 5)
//   2: Pages
//   3: Courier Font
//   4: Signature Dictionary (/adbe.pkcs7.detached)
//   5: Signature Widget Annotation (on Page 1)
//   6..: Page + Content stream pairs
func assemblePDFWithSignaturePlaceholder(pages [][]string, signerName string) ([]byte, int, int, error) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	numPages := len(pages)
	totalObjs := 5 + numPages*2
	offsets := make([]int, totalObjs+1)

	writeObj := func(id int, body string) {
		offsets[id] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, body)
	}

	// Object 1: Catalog
	writeObj(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /SigFlags 3 >> >>")

	// Object 2: Pages
	var kids []string
	for p := 0; p < numPages; p++ {
		pageObjID := 6 + p*2
		kids = append(kids, fmt.Sprintf("%d 0 R", pageObjID))
	}
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), numPages))

	// Object 3: Monospace Courier font
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

	// Object 4: Signature dictionary with fixed-width placeholders
	offsets[4] = buf.Len()
	buf.WriteString("4 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached ")
	fmt.Fprintf(&buf, "/Name (%s) ", escapePDFLiteral(sanitizePDFAscii(signerName)))
	buf.WriteString("/Reason (SurakshaNet Tamper-Evident Evidence Export) ")
	buf.WriteString("/ByteRange ")
	byteRangeOffset := buf.Len()
	buf.WriteString("[0000000000 0000000000 0000000000 0000000000] /Contents <")
	contentsHexOffset := buf.Len()
	buf.WriteString(strings.Repeat("0", sigHexCapacity))
	buf.WriteString("> >>\nendobj\n")

	// Object 5: Invisible Signature Widget attached to page 1 (obj 6)
	writeObj(5, "<< /Type /Annot /Subtype /Widget /FT /Sig /T (SurakshaNetSignature) /V 4 0 R /P 6 0 R /Rect [0 0 0 0] /F 132 >>")

	// Objects 6..: Page + Stream pairs
	for p, pageLines := range pages {
		pageObjID := 6 + p*2
		contentObjID := pageObjID + 1

		var stream bytes.Buffer
		stream.WriteString("BT\n/F1 9 Tf\n36 760 Td\n12 TL\n")
		for idx, line := range pageLines {
			if idx == 0 {
				fmt.Fprintf(&stream, "(%s) Tj\n", escapePDFLiteral(line))
			} else {
				fmt.Fprintf(&stream, "T* (%s) Tj\n", escapePDFLiteral(line))
			}
		}
		fmt.Fprintf(&stream, "T* (--- Page %d of %d | Digitally Signed by SurakshaNet Parent Key ---) Tj\nET\n", p+1, numPages)

		annots := ""
		if p == 0 {
			annots = " /Annots [5 0 R]"
		}
		writeObj(pageObjID, fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R%s >>",
			contentObjID, annots,
		))
		writeObj(contentObjID, fmt.Sprintf(
			"<< /Length %d >>\nstream\n%sendstream",
			stream.Len(), stream.String(),
		))
	}

	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", totalObjs+1)
	for i := 1; i <= totalObjs; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", totalObjs+1, xrefOffset)

	return buf.Bytes(), byteRangeOffset, contentsHexOffset, nil
}
