// Issues the certificates for the Vector and seal-verifier hop. Two CAs, one per direction, so
// that Vector's own client key cannot post to Vector's trusted source. CA keys stay in memory and
// are never written, so no further certificate can be issued without replacing both trust files.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func serial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func write(path string, kind string, der []byte, mode os.FileMode) {
	data := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if err := os.WriteFile(path, data, mode); err != nil {
		log.Fatal(err)
	}
}

func newAuthority(name, path string, days int) authority {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	write(path, "CERTIFICATE", der, 0o644)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return authority{cert, key}
}

func issue(ca authority, name, prefix string, days int, usage ...x509.ExtKeyUsage) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		log.Fatal(err)
	}
	write(prefix+".crt", "CERTIFICATE", der, 0o644)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	write(prefix+".key", "PRIVATE KEY", keyDER, 0o600)
}

func main() {
	out := flag.String("out", "", "output folder, which must not already exist")
	days := flag.Int("days", 825, "certificate lifetime")
	flag.Parse()
	if *out == "" {
		log.Fatal("-out is required")
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
		log.Fatal(err)
	}
	vectorCA := newAuthority("siem-vector-ca", filepath.Join(*out, "vector-ca.crt"), *days)
	verifierCA := newAuthority("siem-verifier-ca", filepath.Join(*out, "verifier-ca.crt"), *days)
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	issue(vectorCA, "siem-vector", filepath.Join(*out, "vector"), *days, both...)
	issue(verifierCA, "siem-seal-verifier", filepath.Join(*out, "verifier"), *days, both...)
}
