package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

func GenerateX509KeyPair(commonName string) (*tls.Certificate, error) {
	template := &x509.Certificate{
		IsCA: true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},     // irrelevant as this thing is self-signed
		SerialNumber:          big.NewInt(1), // FIXME
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("GenerateKey: ")
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	fmt.Printf("publicKey (%T): %v\n", publicKey, publicKey)

	certDer, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		fmt.Printf("CreateCertificate: ")
		return nil, err
	}

	// cert, err := x509.ParseCertificate(certDer)
	// if err != nil {
	// 	fmt.Printf("ParseCertificate: ")
	// 	return nil, err
	// }

	return &tls.Certificate{
		Certificate: [][]byte{certDer},
		PrivateKey:  privateKey,
	}, nil
}
