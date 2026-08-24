package mylego

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
)

func TestNewUsesConfiguredPath(t *testing.T) {
	configPath := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configPath)

	lego, err := New(&CertConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(configPath, "cert")
	if lego.getPath() != want {
		t.Fatalf("certificate path = %q, want %q", lego.getPath(), want)
	}
}

func TestCachedCertificateMethods(t *testing.T) {
	configPath := t.TempDir()
	t.Setenv("XRAY_LOCATION_CONFIG", configPath)
	t.Setenv("XRAYR_TEST_DNS_TOKEN", "")

	for _, test := range []struct {
		name string
		mode string
		call func(*LegoCMD) (string, string, error)
	}{
		{
			name: "dns",
			mode: "dns",
			call: func(l *LegoCMD) (string, string, error) { return l.DNSCert() },
		},
		{
			name: "http",
			mode: "http",
			call: func(l *LegoCMD) (string, string, error) { return l.HTTPCert() },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			domain := test.name + ".example.invalid"
			lego, err := New(&CertConfig{
				CertMode:   test.mode,
				CertDomain: domain,
				Email:      "test@example.invalid",
				DNSEnv: map[string]string{
					"xrayr_test_dns_token": "fixture",
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			storage := NewCertificatesStorage(lego.path)
			storage.CreateRootFolder()
			storage.SaveResource(newTestCertificate(t, domain, 60*24*time.Hour))

			certPath, keyPath, err := test.call(lego)
			if err != nil {
				t.Fatal(err)
			}
			if certPath != storage.GetFileName(domain, ".crt") {
				t.Fatalf("certificate path = %q, want %q", certPath, storage.GetFileName(domain, ".crt"))
			}
			if keyPath != storage.GetFileName(domain, ".key") {
				t.Fatalf("key path = %q, want %q", keyPath, storage.GetFileName(domain, ".key"))
			}
		})
	}

	if got := os.Getenv("XRAYR_TEST_DNS_TOKEN"); got != "fixture" {
		t.Fatalf("DNS environment value = %q, want fixture", got)
	}
}

func TestCertificateStorageAndFreshRenewal(t *testing.T) {
	domain := "fresh.example.invalid"
	storage := NewCertificatesStorage(t.TempDir())
	storage.CreateRootFolder()
	resource := newTestCertificate(t, domain, 60*24*time.Hour)
	storage.SaveResource(resource)

	loaded := storage.ReadResource(domain)
	if loaded.Domain != domain {
		t.Fatalf("resource domain = %q, want %q", loaded.Domain, domain)
	}
	certificates, err := storage.ReadCertificate(domain, ".crt")
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || certificates[0].Subject.CommonName != domain {
		t.Fatalf("unexpected stored certificate: %#v", certificates)
	}

	renewed, err := renewForDomains(domain, nil, storage)
	if err != nil {
		t.Fatal(err)
	}
	if renewed {
		t.Fatal("fresh certificate was unexpectedly renewed")
	}
}

func TestAccountPrivateKeyRoundTrip(t *testing.T) {
	storage := NewAccountsStorage(&LegoCMD{
		C:    &CertConfig{Email: "test@example.invalid"},
		path: t.TempDir(),
	})

	first, ok := storage.GetPrivateKey(certcrypto.EC256).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected first private key type %T", first)
	}
	second, ok := storage.GetPrivateKey(certcrypto.EC256).(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("unexpected second private key type %T", second)
	}
	if first.D.Cmp(second.D) != 0 {
		t.Fatal("stored account private key changed after reload")
	}
}

func TestCertificatePathsAreInstanceLocal(t *testing.T) {
	first := &LegoCMD{path: filepath.Join(t.TempDir(), "first")}
	second := &LegoCMD{path: filepath.Join(t.TempDir(), "second")}
	for _, lego := range []*LegoCMD{first, second} {
		storage := NewCertificatesStorage(lego.path)
		storage.CreateRootFolder()
		storage.SaveResource(newTestCertificate(t, "node.example.invalid", 60*24*time.Hour))
	}

	firstCert, _, err := first.checkCertFile("node.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	secondCert, _, err := second.checkCertFile("node.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if firstCert == secondCert {
		t.Fatalf("independent certificate stores resolved to the same path %q", firstCert)
	}
}

func newTestCertificate(t *testing.T, domain string, lifetime time.Duration) *certificate.Resource {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return &certificate.Resource{
		Domain:      domain,
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}
