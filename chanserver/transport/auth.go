package transport

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
)

type Peers struct {
	peers map[string][]byte
	mutex *sync.RWMutex
}

func NewPeers() *Peers {
	return &Peers{
		peers: make(map[string][]byte),
		mutex: &sync.RWMutex{},
	}
}

func (p *Peers) Update(id string, tlsSignature []byte) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.peers[id] = tlsSignature
}

func (p *Peers) Signature(id string) []byte {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.peers[id]
}

func SignatureAuthenticator(conn net.Conn, peers *Peers) error {
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

	fmt.Printf("SignatureAuthenticator: %T: ConnectionState: %v\n",
		conn, state)

	cn := peerCert.Subject.CommonName

	fmt.Printf("CN: %s\n", cn)
	fmt.Printf("Signature (%v): %x\n", peerCert.SignatureAlgorithm, peerCert.Signature)

	expectedSig := peers.Signature(cn)

	if expectedSig == nil {
		errMsg := fmt.Sprintf("SignatureAuthenticator: Peer '%s' not known", cn)
		log.Print(errMsg)
		return errors.New(errMsg)
	} else if !bytes.Equal(expectedSig, peerCert.Signature) {
		// FIXME constant-time comparison?
		errMsg := fmt.Sprintf("SignatureAuthenticator: Wrong signature for '%s', expected %v",
			cn, expectedSig)
		log.Print(errMsg)
		return errors.New(errMsg)
	}

	log.Printf("Signature for '%s' ok.", cn)

	// TODO Think about checking more stuff: date/time, ...

	return nil
}
