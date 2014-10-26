package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
)

func TestAuthenticator(conn net.Conn) error {
	tlsConn := conn.(*tls.Conn)
	tlsConn.Handshake()
	state := tlsConn.ConnectionState()
	peerCerts := state.PeerCertificates

	if len(peerCerts) != 1 {
		return errors.New(
			fmt.Sprintf("Expected exactly one peer certificate, got more or less: %v",
				len(peerCerts)))
	}
	peerCert := peerCerts[0]

	fmt.Printf("TestAuthenticator: %T: ConnectionState: %v\n",
		conn, state)

	fmt.Printf("CN: %s\n", peerCert.Subject.CommonName)
	fmt.Printf("Signature (%v): %x\n", peerCert.SignatureAlgorithm, peerCert.Signature)

	// TODO check stuff: signature, date/time, ...

	return nil
}
