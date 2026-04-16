package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testMasterKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func newTestCA(t *testing.T, opts Options) *SoftCA {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = t.TempDir()
	}
	ca, err := New(testMasterKey(), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return ca
}

func TestNew_FreshInit_WritesFilesWithExpectedPerms(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "ca")
	ca := newTestCA(t, Options{Dir: caDir})
	if len(ca.RootPEM()) == 0 {
		t.Fatal("RootPEM is empty")
	}

	certInfo, err := os.Stat(filepath.Join(caDir, rootCertFile))
	if err != nil {
		t.Fatalf("stat cert: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert perm = %o, want 0644", certInfo.Mode().Perm())
	}
	keyInfo, err := os.Stat(filepath.Join(caDir, rootKeyFile))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key perm = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestNew_Reload_YieldsSameRoot(t *testing.T) {
	caDir := t.TempDir()
	key := testMasterKey()
	ca1, err := New(key, Options{Dir: caDir})
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	ca2, err := New(key, Options{Dir: caDir})
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	if !bytes.Equal(ca1.RootPEM(), ca2.RootPEM()) {
		t.Error("RootPEM differs between instances")
	}
	leaf, err := ca1.MintLeaf("verify.example.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca2.RootPEM()) {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "verify.example.com",
	}); err != nil {
		t.Errorf("verify leaf against reloaded root: %v", err)
	}
}

func TestNew_WrongMasterKey_Fails(t *testing.T) {
	caDir := t.TempDir()
	if _, err := New(testMasterKey(), Options{Dir: caDir}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	wrong := make([]byte, 32)
	wrong[0] = 0xFF
	if _, err := New(wrong, Options{Dir: caDir}); err == nil {
		t.Error("expected error with wrong master key, got nil")
	}
}

func TestMintLeaf_VerifiesAgainstRoot(t *testing.T) {
	ca := newTestCA(t, Options{LeafTTL: time.Hour})
	cert, err := ca.MintLeaf("example.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("Leaf is nil")
	}
	if cert.Leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want example.com", cert.Leaf.Subject.CommonName)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", cert.Leaf.DNSNames)
	}
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("PrivateKey is not *ecdsa.PrivateKey")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.RootPEM()) {
		t.Fatal("AppendCertsFromPEM failed")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSName:   "example.com",
	}); err != nil {
		t.Errorf("Verify: %v", err)
	}

	now := time.Now()
	if cert.Leaf.NotAfter.Before(now.Add(55*time.Minute)) || cert.Leaf.NotAfter.After(now.Add(65*time.Minute)) {
		t.Errorf("NotAfter = %v, expected ~1h from %v", cert.Leaf.NotAfter, now)
	}
}

func TestMintLeaf_CacheHit_ReturnsSamePointer(t *testing.T) {
	ca := newTestCA(t, Options{})
	a, err := ca.MintLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.MintLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("cache hit returned different pointers")
	}
}

func TestMintLeaf_DifferentSNI_DifferentCerts(t *testing.T) {
	ca := newTestCA(t, Options{})
	a, err := ca.MintLeaf("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.MintLeaf("b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("different SNIs returned same pointer")
	}
	if a.Leaf.DNSNames[0] == b.Leaf.DNSNames[0] {
		t.Error("DNSNames match despite different SNIs")
	}
}

func TestMintLeaf_LRUEvictsLeastRecent(t *testing.T) {
	ca := newTestCA(t, Options{CacheSize: 2})
	a1, err := ca.MintLeaf("a.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.MintLeaf("b.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.MintLeaf("c.com"); err != nil {
		t.Fatal(err)
	}
	a2, err := ca.MintLeaf("a.com")
	if err != nil {
		t.Fatal(err)
	}
	if a1 == a2 {
		t.Error("a.com should have been evicted and regenerated")
	}
}

func TestMintLeaf_RegeneratesWhenNearExpiry(t *testing.T) {
	current := time.Now()
	ca := newTestCA(t, Options{
		LeafTTL: time.Hour,
		Clock:   func() time.Time { return current },
	})
	first, err := ca.MintLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	current = first.Leaf.NotAfter.Add(-1 * time.Minute)
	second, err := ca.MintLeaf("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("near-expiry cached leaf should have been regenerated")
	}
}

func TestMintLeaf_InvalidSNI(t *testing.T) {
	ca := newTestCA(t, Options{})
	cases := []string{
		"",
		"foo bar",
		"has/slash",
		strings.Repeat("a", 254),
		"-leading.com",
		"trailing-.com",
		".leading-dot.com",
		"double..dot.com",
		strings.Repeat("a", 64) + ".com",
	}
	for _, sni := range cases {
		if _, err := ca.MintLeaf(sni); err == nil {
			t.Errorf("MintLeaf(%q) = nil error, want error", sni)
		}
	}
}

func TestMintLeaf_IPAddressPopulatesIPSAN(t *testing.T) {
	ca := newTestCA(t, Options{})
	cert, err := ca.MintLeaf("127.0.0.1")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v, want [127.0.0.1]", cert.Leaf.IPAddresses)
	}
	if len(cert.Leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty", cert.Leaf.DNSNames)
	}
}

func TestRootPEM_IsValidCACert(t *testing.T) {
	ca := newTestCA(t, Options{})
	block, _ := pem.Decode(ca.RootPEM())
	if block == nil {
		t.Fatal("failed to decode root PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if !cert.IsCA {
		t.Error("root cert is not marked as CA")
	}
	if cert.Subject.CommonName != rootCommonName {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, rootCommonName)
	}
}
