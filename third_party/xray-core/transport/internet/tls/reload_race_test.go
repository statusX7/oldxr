package tls

import (
	gotls "crypto/tls"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

func TestCertificateStoreConcurrentReload(t *testing.T) {
	firstDefinition := ParseCertificate(cert.MustGenerate(nil, cert.CommonName("first.example")))
	secondDefinition := ParseCertificate(cert.MustGenerate(nil, cert.CommonName("second.example")))
	first := loadX509KeyPair(firstDefinition.Certificate, firstDefinition.Key)
	second := loadX509KeyPair(secondDefinition.Certificate, secondDefinition.Key)
	if first == nil || second == nil {
		t.Fatal("failed to build test certificates")
	}

	store := new(certificateStore)
	slot := store.append(first)
	getCertificate := getNewGetCertificateFunc(store, false)

	start := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		<-start
		for i := 0; i < 10_000; i++ {
			if i%2 == 0 {
				slot.Store(second)
			} else {
				slot.Store(first)
			}
		}
	}()

	close(start)
	for i := 0; i < 10_000; i++ {
		certificate, err := getCertificate(&gotls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		name := certificate.Leaf.Subject.CommonName
		if name != "first.example" && name != "second.example" {
			t.Fatalf("unexpected certificate: %q", name)
		}
	}
	writer.Wait()
}
