package ca

import "crypto/tls"

// Provider issues TLS server certificates for arbitrary SNIs.
// Implementations must be safe for concurrent use.
type Provider interface {
	// MintLeaf returns a leaf certificate whose SAN covers sni,
	// signed by this CA's root. Implementations may cache results.
	MintLeaf(sni string) (*tls.Certificate, error)

	// RootPEM returns the root CA certificate in PEM form.
	// It is safe to expose publicly.
	RootPEM() []byte
}
