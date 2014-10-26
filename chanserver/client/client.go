package main

import (
	"crypto/tls"
	// "fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"

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

	cert := "../certs/client.crt"
	key := "../certs/client.key"

	keyPair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		log.Fatal(err)
	}

	certs := []tls.Certificate{keyPair}

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
