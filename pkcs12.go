package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	err := Pkcs12Gen()
	if err != nil {
		log.Fatal(err)
	}
}

func Pkcs12Gen() error {
	baseDir, err := os.Getwd()
	if err != nil {
		return err
	}

	priPath := path.Join(baseDir, "priv.pfx")
	pubPath := path.Join(baseDir, "pub.pem")

	keyBytes, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	if err := keyBytes.Validate(); err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"EN"},
			Organization:       []string{"org"},
			OrganizationalUnit: []string{"org"},
			Locality:           []string{"city"},
			Province:           []string{"province"},
			CommonName:         "name",
		},
		// #4 the certificate should have start/end life
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &keyBytes.PublicKey, keyBytes)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	pfxBytes, err := pkcs12.Encode(rand.Reader, keyBytes, cert, []*x509.Certificate{}, pkcs12.DefaultPassword)
	if err != nil {
		return err
	}

	if _, _, err := pkcs12.Decode(pfxBytes, pkcs12.DefaultPassword); err != nil {
		return err
	}

	if err := os.WriteFile(
		priPath,
		pfxBytes,
		os.ModePerm,
	); err != nil {
		return err
	}
	certOut, err := os.Create(pubPath)

	if err != nil {
		return err
	}

	if err := pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}); err != nil {
		return err
	}

	if err := certOut.Close(); err != nil {
		return err
	}

	fmt.Printf("the certificate has been generated: \n\tpfx: %s\n\tpem: %s\n", priPath, pubPath)
	fingerprint, err := getFingerprint(*cert)
	if err != nil {
		return err
	}
	fmt.Printf("Fingerprint: %s\n", fingerprint)

	return nil
}

func getFingerprint(certificate x509.Certificate) (string, error) {
	// generate fingerprint with sha256
	// can also use md5, sha1, etc.
	fingerprint := sha256.Sum256(certificate.Raw)

	var buf bytes.Buffer
	for _, f := range fingerprint {
		_, err := fmt.Fprintf(&buf, "%02x", f)
		if err != nil {
			return "", err
		}
	}
	return buf.String(), nil
}
