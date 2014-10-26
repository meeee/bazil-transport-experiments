package main

import (
	"crypto/tls"
	// "fmt"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"

	"frister.net/experiments/chanserver/crypto"
	"frister.net/experiments/chanserver/transport"
)

type RemoteCommand struct {
	Cmd        string
	Args       []string
	Stdin      io.Writer
	Stdout     io.Reader
	Stderr     io.Reader
	StatusChan libchan.Sender
}

type CommandResponse struct {
	Status int
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: <command> [<arg> ]")
	}

	var client net.Conn
	var err error

	certFile := "../certs/client.crt"
	keyFile := "../certs/client.key"

	tlsKeyPair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair failed: %v", err)
	}

	cert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	if err != nil {
		log.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	ownPair, err := crypto.LoadOrCreateKeyPair("../certs/client.nacl.json")
	if err != nil {
		log.Fatalf("crypto.LoadOrCreateKeyPair failed for client: %v", err)
	}
	peerPair, err := crypto.LoadOrCreateKeyPair("../certs/server.nacl.json")
	if err != nil {
		log.Fatalf("crypto.LoadOrCreateKeyPair failed for server: %v", err)
	}

	box, nonce, err := crypto.Seal(cert.Signature, peerPair.PublicKey, ownPair.PrivateKey)
	if err != nil {
		log.Fatalf("crypto.Seal failed: %v", err)
	}

	type HandshakeMessage struct {
		Nonce               *[24]byte
		SealedCertSignature []byte
	}
	handshakeMessage := HandshakeMessage{nonce, box}
	enc, err := json.Marshal(handshakeMessage)
	if err != nil {
		log.Fatalf("json.Marshall failed: %v", err)
	}

	log.Printf("Marshalled handshake message: %s", enc)

	certs := []tls.Certificate{tlsKeyPair}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		Certificates:       certs,
	}
	client, err = tls.Dial("tcp", "127.0.0.1:9323", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	if transport.TestAuthenticator(client) != nil {
		log.Fatal(err)
	}

	transport_, err := spdy.NewClientTransport(client)
	if err != nil {
		log.Fatal(err)
	}
	sender, err := transport_.NewSendChannel()
	if err != nil {
		log.Fatal(err)
	}

	receiver, remoteSender := libchan.Pipe()

	command := &RemoteCommand{
		Cmd:        os.Args[1],
		Args:       os.Args[2:],
		Stdin:      os.Stdin,
		Stdout:     os.Stdout,
		Stderr:     os.Stderr,
		StatusChan: remoteSender,
	}

	err = sender.Send(command)
	if err != nil {
		log.Fatal(err)
	}

	response := &CommandResponse{}
	err = receiver.Receive(response)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(response.Status)
}
