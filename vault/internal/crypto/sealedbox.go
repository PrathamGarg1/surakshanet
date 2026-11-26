package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

const (
	SealedBoxVersion = 1
	SealedBoxAlg     = "ECDH-P256-HKDF-SHA256-AES256GCM"
	hkdfInfo         = "surakshanet-sealedbox-v1"
	scryptN          = 32768
	scryptR          = 8
	scryptP          = 1
	scryptKeyLen     = 32
)

// SealedBox is an anonymous public-key encrypted envelope.
// Once sealed with the parent's public key, not even the sender can decrypt it.
type SealedBox struct {
	Version int    `json:"v"`
	Alg     string `json:"alg"`
	KeyID   string `json:"kid"`
	EPK     string `json:"epk"`
	Nonce   string `json:"nonce"`
	CT      string `json:"ct"`
}

// ParentPublicBundle holds only non-secret public material safe to install
// into Chrome managed policy on the child's machine.
type ParentPublicBundle struct {
	Version         int    `json:"version"`
	KeyID           string `json:"key_id"`
	ParentPublicKey string `json:"parent_public_key"`
	PDFCertPEM      string `json:"pdf_cert_pem"`
	CreatedAt       string `json:"created_at"`
}

// ParentKeyMaterial holds decrypted parent private keys in memory.
type ParentKeyMaterial struct {
	ECDHPrivate    *ecdh.PrivateKey
	ECDHPublicRaw  []byte
	KeyID          string
	PDFSignPrivate *ecdsa.PrivateKey
	PDFCert        *x509.Certificate
	PDFCertPEM     string
	CreatedAt      string
}

type encryptedParentKeyFile struct {
	Version         int    `json:"version"`
	KDF             string `json:"kdf"`
	ScryptN         int    `json:"scrypt_n"`
	ScryptR         int    `json:"scrypt_r"`
	ScryptP         int    `json:"scrypt_p"`
	Salt            string `json:"salt"`
	Nonce           string `json:"nonce"`
	KeyID           string `json:"key_id"`
	ParentPublicKey string `json:"parent_public_key"`
	PDFCertPEM      string `json:"pdf_cert_pem"`
	CreatedAt       string `json:"created_at"`
	Ciphertext      string `json:"ciphertext"`
}

type plainKeyPayload struct {
	ECDHPrivateRaw    string `json:"ecdh_private_raw"`
	PDFSignPrivateDER string `json:"pdf_sign_private_der"`
}

// KeyFingerprint returns a stable 16-hex-character key identifier for a raw public key.
func KeyFingerprint(pubRaw []byte) string {
	sum := sha256.Sum256(pubRaw)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKeyBase64 decodes a base64 uncompressed P-256 public key (65 bytes).
func ParsePublicKeyBase64(b64 string) (*ecdh.PublicKey, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base64 public key: %w", err)
	}
	pub, err := ecdh.P256().NewPublicKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid P-256 public key: %w", err)
	}
	return pub, raw, nil
}

// GenerateParentKeyMaterial creates a fresh Parent ECDH keypair and a matching
// ECDSA P-256 signing key + self-signed X.509 certificate for PDF signatures.
func GenerateParentKeyMaterial(parentLabel string) (*ParentKeyMaterial, error) {
	if parentLabel == "" {
		parentLabel = "SurakshaNet Parent Guardian"
	}
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}
	pubRaw := ecdhPriv.PublicKey().Bytes()
	kid := KeyFingerprint(pubRaw)

	signPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate PDF signing key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate cert serial: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s (%s)", parentLabel, kid),
			Organization: []string{"SurakshaNet Local Evidence Vault"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signPriv.PublicKey, signPriv)
	if err != nil {
		return nil, fmt.Errorf("create self-signed PDF cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse created cert: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	return &ParentKeyMaterial{
		ECDHPrivate:    ecdhPriv,
		ECDHPublicRaw:  pubRaw,
		KeyID:          kid,
		PDFSignPrivate: signPriv,
		PDFCert:        cert,
		PDFCertPEM:     certPEM,
		CreatedAt:      now.Format(time.RFC3339),
	}, nil
}

// PublicBundle returns the public-only view safe to place on the child's machine.
func (k *ParentKeyMaterial) PublicBundle() *ParentPublicBundle {
	return &ParentPublicBundle{
		Version:         1,
		KeyID:           k.KeyID,
		ParentPublicKey: base64.StdEncoding.EncodeToString(k.ECDHPublicRaw),
		PDFCertPEM:      k.PDFCertPEM,
		CreatedAt:       k.CreatedAt,
	}
}

// SaveEncryptedKeyFile encrypts the parent private keys using scrypt + AES-256-GCM
// and writes the file with mode 0600.
func SaveEncryptedKeyFile(path string, mat *ParentKeyMaterial, passphrase string) error {
	if len(passphrase) < 8 {
		return errors.New("parent key passphrase must be at least 8 characters")
	}
	signDER, err := x509.MarshalPKCS8PrivateKey(mat.PDFSignPrivate)
	if err != nil {
		return fmt.Errorf("marshal PDF signing key: %w", err)
	}
	plain := plainKeyPayload{
		ECDHPrivateRaw:    base64.StdEncoding.EncodeToString(mat.ECDHPrivate.Bytes()),
		PDFSignPrivateDER: base64.StdEncoding.EncodeToString(signDER),
	}
	plainBytes, err := json.Marshal(plain)
	if err != nil {
		return err
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	kek, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	aad := []byte("surakshanet-parent-key-v1:" + mat.KeyID)
	ct := gcm.Seal(nil, nonce, plainBytes, aad)

	doc := encryptedParentKeyFile{
		Version:         1,
		KDF:             "scrypt-aes256gcm",
		ScryptN:         scryptN,
		ScryptR:         scryptR,
		ScryptP:         scryptP,
		Salt:            base64.StdEncoding.EncodeToString(salt),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
		KeyID:           mat.KeyID,
		ParentPublicKey: base64.StdEncoding.EncodeToString(mat.ECDHPublicRaw),
		PDFCertPEM:      mat.PDFCertPEM,
		CreatedAt:       mat.CreatedAt,
		Ciphertext:      base64.StdEncoding.EncodeToString(ct),
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}

// LoadEncryptedKeyFile decrypts a passphrase-protected parent key bundle.
func LoadEncryptedKeyFile(path string, passphrase string) (*ParentKeyMaterial, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc encryptedParentKeyFile
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse key file: %w", err)
	}
	if doc.Version != 1 || doc.KDF != "scrypt-aes256gcm" {
		return nil, fmt.Errorf("unsupported key file format (version=%d kdf=%s)", doc.Version, doc.KDF)
	}
	salt, err := base64.StdEncoding.DecodeString(doc.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(doc.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(doc.Ciphertext)
	if err != nil {
		return nil, err
	}
	kek, err := scrypt.Key([]byte(passphrase), salt, doc.ScryptN, doc.ScryptR, doc.ScryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := []byte("surakshanet-parent-key-v1:" + doc.KeyID)
	plainBytes, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("decryption failed: invalid passphrase or corrupted key file")
	}

	var plain plainKeyPayload
	if err := json.Unmarshal(plainBytes, &plain); err != nil {
		return nil, err
	}
	ecdhRaw, err := base64.StdEncoding.DecodeString(plain.ECDHPrivateRaw)
	if err != nil {
		return nil, err
	}
	ecdhPriv, err := ecdh.P256().NewPrivateKey(ecdhRaw)
	if err != nil {
		return nil, err
	}
	signDER, err := base64.StdEncoding.DecodeString(plain.PDFSignPrivateDER)
	if err != nil {
		return nil, err
	}
	signAny, err := x509.ParsePKCS8PrivateKey(signDER)
	if err != nil {
		return nil, err
	}
	signPriv, ok := signAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unexpected PDF signing key type")
	}
	blockPEM, _ := pem.Decode([]byte(doc.PDFCertPEM))
	if blockPEM == nil {
		return nil, errors.New("invalid PDF certificate PEM in key file")
	}
	cert, err := x509.ParseCertificate(blockPEM.Bytes)
	if err != nil {
		return nil, err
	}

	pubRaw := ecdhPriv.PublicKey().Bytes()
	return &ParentKeyMaterial{
		ECDHPrivate:    ecdhPriv,
		ECDHPublicRaw:  pubRaw,
		KeyID:          KeyFingerprint(pubRaw),
		PDFSignPrivate: signPriv,
		PDFCert:        cert,
		PDFCertPEM:     doc.PDFCertPEM,
		CreatedAt:      doc.CreatedAt,
	}, nil
}

func deriveSealedBoxKey(sharedSecret, ephPubRaw, recipientPubRaw []byte) ([]byte, []byte, error) {
	saltHash := sha256.New()
	saltHash.Write(ephPubRaw)
	saltHash.Write(recipientPubRaw)
	salt := saltHash.Sum(nil)

	r := hkdf.New(sha256.New, sharedSecret, salt, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, err
	}

	aad := make([]byte, 0, len(hkdfInfo)+len(ephPubRaw)+len(recipientPubRaw))
	aad = append(aad, []byte(hkdfInfo)...)
	aad = append(aad, ephPubRaw...)
	aad = append(aad, recipientPubRaw...)
	return key, aad, nil
}

// Seal encrypts plaintext to recipientPubRaw (65-byte uncompressed P-256 point)
// using an ephemeral ECDH keypair + HKDF-SHA256 + AES-256-GCM.
func Seal(plaintext []byte, recipientPubRaw []byte) (*SealedBox, error) {
	recipientPub, err := ecdh.P256().NewPublicKey(recipientPubRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPubRaw := ephPriv.PublicKey().Bytes()
	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	key, aad, err := deriveSealedBoxKey(shared, ephPubRaw, recipientPubRaw)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return &SealedBox{
		Version: SealedBoxVersion,
		Alg:     SealedBoxAlg,
		KeyID:   KeyFingerprint(recipientPubRaw),
		EPK:     base64.StdEncoding.EncodeToString(ephPubRaw),
		Nonce:   base64.StdEncoding.EncodeToString(nonce),
		CT:      base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// Open decrypts a SealedBox using the parent's ECDH P-256 private key.
func Open(box *SealedBox, recipientPriv *ecdh.PrivateKey) ([]byte, error) {
	if box == nil {
		return nil, errors.New("nil sealed box")
	}
	if box.Version != SealedBoxVersion || box.Alg != SealedBoxAlg {
		return nil, fmt.Errorf("unsupported sealed box version=%d alg=%s", box.Version, box.Alg)
	}
	ephPubRaw, err := base64.StdEncoding.DecodeString(box.EPK)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral pubkey: %w", err)
	}
	ephPub, err := ecdh.P256().NewPublicKey(ephPubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse ephemeral pubkey: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(box.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(box.CT)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	recipientPubRaw := recipientPriv.PublicKey().Bytes()
	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}
	key, aad, err := deriveSealedBoxKey(shared, ephPubRaw, recipientPubRaw)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("sealed box authentication failed: wrong private key or tampered ciphertext")
	}
	return plaintext, nil
}
