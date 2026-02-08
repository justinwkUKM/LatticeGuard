package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"
)

/**
 * RTPN Settlement Node
 * Mutual TLS client for Real-Time Payment Network settlement.
 * Used for: RENTAS, DuitNow Interbank Settlement, MEPS+.
 */

// VULNERABILITY: ECDSA P-256 certificates for mTLS (Shor-vulnerable)
func generateSettlementNodeCert() (tls.Certificate, error) {
	// Generate ECDSA private key - QUANTUM VULNERABLE
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"PayNet Malaysia"},
			CommonName:    "settlement-node.paynet.my",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0), // 2-year validity
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// Connect to RENTAS settlement gateway with mTLS
func connectToSettlementGateway(gatewayURL string) error {
	cert, err := generateSettlementNodeCert()
	if err != nil {
		return fmt.Errorf("failed to generate mTLS cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Demo only - production would verify CA
		MinVersion:         tls.VersionTLS12,
		// VULNERABILITY: No PQC cipher suites configured
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}

	resp, err := client.Get(gatewayURL)
	if err != nil {
		return fmt.Errorf("settlement connection failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Connected to settlement gateway: %s\n", resp.Status)
	return nil
}

func main() {
	fmt.Println("RTPN Settlement Node Starting...")
	
	// Simulate connection to RENTAS gateway
	err := connectToSettlementGateway("https://rentas.bnm.gov.my/settlement")
	if err != nil {
		fmt.Printf("Settlement error: %v\n", err)
	}
}
