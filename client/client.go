package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"

	"github.com/meeee/bazil-transport-experiments/crypto"
	"github.com/meeee/bazil-transport-experiments/transport"
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

	ownId := "client"
	serverId := "server"
	peers := transport.NewPeers()

	tlsKeyPair, err := transport.GenerateX509KeyPair("client")
	if err != nil {
		fmt.Printf("GenerateX509KeyPair: ")
		log.Fatal(err)
	}

	cert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	if err != nil {
		log.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	err = doHandshake(ownId, serverId, cert.Signature, peers)
	if err != nil {
		log.Fatalf("Handshake failed: %v", err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		Certificates:       []tls.Certificate{*tlsKeyPair},
	}
	client, err = tls.Dial("tcp", "127.0.0.1:9323", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	if transport.SignatureAuthenticator(client, peers) != nil {
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

func doHandshake(ownId string, peerId string, signature []byte, peers *transport.Peers) error {
	msg, err := crypto.BuildHandshakeMessage(ownId, peerId, signature)
	if err != nil {
		log.Printf("BuildHandshakeMessage failed: %v", err)
		return err
	}

	resp, err := http.Post("http://localhost:9322/api/v1/handshake",
		"application/json",
		bytes.NewReader(msg))

	if err != nil {
		return err
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("Handshake request failed: %s", resp.Status)
	}

	receivedPeerId, peerSignature, err := crypto.OpenHandshakeMessage(ownId, resp.Body)
	if err != nil {
		return fmt.Errorf("Opening handshake message failed: %s", err.Error())
	}

	if receivedPeerId != peerId {
		return fmt.Errorf("doHandshake: Received peer id ('%s') is different from expected ('%s')",
			receivedPeerId, peerId)
	}

	peers.Update(peerId, peerSignature)

	return nil
}
