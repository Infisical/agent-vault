package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
)

const (
	rootCertFile     = "ca.crt.pem"
	rootKeyFile      = "ca.key.enc"
	defaultDirName   = "ca"
	defaultLeafTTL   = 24 * time.Hour
	defaultCacheSize = 1024
	rootValidity     = 10 * 365 * 24 * time.Hour
	clockSkew        = 5 * time.Minute
	rootCommonName   = "Agent Vault Root CA"
)

var serialLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Options configures a SoftCA. Zero values pick sensible defaults.
type Options struct {
	Dir       string           // default: ~/.agent-vault/ca
	LeafTTL   time.Duration    // default: 24h
	CacheSize int              // default: 1024
	Clock     func() time.Time // default: time.Now
}

// SoftCA is a software-backed CA that persists its root to disk (with the
// private key encrypted by the caller-supplied master key) and mints
// short-lived ECDSA P-256 leaves on demand, cached by SNI.
type SoftCA struct {
	mu       sync.Mutex
	dir      string
	leafTTL  time.Duration
	clock    func() time.Time
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	rootPEM  []byte
	cache    *lru
}

type encryptedKeyFile struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// New loads an existing CA from opts.Dir or generates a new one.
// masterKey must be 32 bytes (AES-256-GCM); it encrypts/decrypts the root
// private key at rest.
func New(masterKey []byte, opts Options) (*SoftCA, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("masterKey must be 32 bytes, got %d", len(masterKey))
	}

	dir := opts.Dir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("resolving home dir: %w", err)
		}
		dir = filepath.Join(home, ".agent-vault", defaultDirName)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating ca dir: %w", err)
	}

	leafTTL := opts.LeafTTL
	if leafTTL <= 0 {
		leafTTL = defaultLeafTTL
	}
	cacheSize := opts.CacheSize
	if cacheSize <= 0 {
		cacheSize = defaultCacheSize
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}

	ca := &SoftCA{
		dir:     dir,
		leafTTL: leafTTL,
		clock:   clock,
		cache:   newLRU(cacheSize),
	}

	certPath := filepath.Join(dir, rootCertFile)
	keyPath := filepath.Join(dir, rootKeyFile)

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		if err := ca.load(certPath, keyPath, masterKey); err != nil {
			return nil, fmt.Errorf("loading existing CA: %w", err)
		}
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		if err := ca.generate(certPath, keyPath, masterKey); err != nil {
			return nil, fmt.Errorf("generating new CA: %w", err)
		}
	default:
		return nil, fmt.Errorf("inconsistent CA state in %s (cert: %v, key: %v)", dir, certErr, keyErr)
	}
	return ca, nil
}

func (c *SoftCA) load(certPath, keyPath string, masterKey []byte) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading root cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid root cert PEM at %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing root cert: %w", err)
	}

	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading root key: %w", err)
	}
	var enc encryptedKeyFile
	if err := json.Unmarshal(raw, &enc); err != nil {
		return fmt.Errorf("parsing root key file: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		return fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		return fmt.Errorf("decoding ciphertext: %w", err)
	}
	keyDER, err := crypto.Decrypt(ciphertext, nonce, masterKey)
	if err != nil {
		return fmt.Errorf("decrypting root key: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("parsing root key: %w", err)
	}

	c.setRoot(cert, key, certPEM)
	return nil
}

func (c *SoftCA) generate(certPath, keyPath string, masterKey []byte) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating root key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := c.clock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: rootCommonName},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating root cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing freshly created root cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeAtomic(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing root cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling root key: %w", err)
	}
	ciphertext, nonce, err := crypto.Encrypt(keyDER, masterKey)
	if err != nil {
		return fmt.Errorf("encrypting root key: %w", err)
	}
	blob, err := json.Marshal(encryptedKeyFile{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return fmt.Errorf("marshaling encrypted key: %w", err)
	}
	if err := writeAtomic(keyPath, blob, 0600); err != nil {
		return fmt.Errorf("writing root key: %w", err)
	}

	c.setRoot(cert, key, certPEM)
	return nil
}

func (c *SoftCA) setRoot(cert *x509.Certificate, key *ecdsa.PrivateKey, pemBytes []byte) {
	c.rootCert = cert
	c.rootKey = key
	c.rootPEM = pemBytes
}

// RootPEM returns a copy of the root CA certificate in PEM form.
func (c *SoftCA) RootPEM() []byte {
	out := make([]byte, len(c.rootPEM))
	copy(out, c.rootPEM)
	return out
}

// MintLeaf returns a leaf certificate for the given SNI. Results are cached;
// cached entries are returned only if they remain valid beyond a clock-skew
// buffer, so the caller never receives a cert that may expire mid-handshake.
func (c *SoftCA) MintLeaf(sni string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.clock()
	if existing, ok := c.cache.get(sni); ok {
		if existing.Leaf != nil && existing.Leaf.NotAfter.After(now.Add(clockSkew)) {
			return existing, nil
		}
	}

	isIP, err := validateSNI(sni)
	if err != nil {
		return nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(c.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if isIP {
		tmpl.IPAddresses = []net.IP{net.ParseIP(sni)}
	} else {
		tmpl.DNSNames = []string{sni}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &leafKey.PublicKey, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("creating leaf cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing leaf cert: %w", err)
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
	c.cache.add(sni, tlsCert)
	return tlsCert, nil
}

func validateSNI(sni string) (bool, error) {
	if sni == "" {
		return false, errors.New("empty SNI")
	}
	if len(sni) > 253 {
		return false, errors.New("SNI exceeds 253 bytes")
	}
	if ip := net.ParseIP(sni); ip != nil {
		return true, nil
	}
	for _, label := range strings.Split(sni, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false, fmt.Errorf("invalid SNI label length: %d", len(label))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false, fmt.Errorf("SNI label cannot start or end with hyphen: %q", label)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false, fmt.Errorf("invalid SNI character %q", r)
			}
		}
	}
	return false, nil
}

func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return n, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

var _ Provider = (*SoftCA)(nil)
