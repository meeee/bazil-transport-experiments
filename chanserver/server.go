package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"syscall"

	"github.com/docker/libchan"
	"github.com/docker/libchan/spdy"

	"frister.net/experiments/chanserver/crypto"
	"frister.net/experiments/chanserver/transport"
)

type RemoteCommand struct {
	Cmd        string
	Args       []string
	Stdin      io.Reader
	Stdout     io.WriteCloser
	Stderr     io.WriteCloser
	StatusChan libchan.Sender
}

type CommandResponse struct {
	Status int
}

func main() {
	keyPair, err := transport.GenerateX509KeyPair("server")
	if err != nil {
		fmt.Printf("GenerateX509KeyPair: ")
		log.Fatal(err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		Certificates:       []tls.Certificate{*keyPair},
		MinVersion:         tls.VersionTLS10,
	}

	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatalf("x509.ParseCertificate failed: %v", err)
	}

	peers := transport.NewPeers()

	go runWebServer(peers, cert.Signature)
	runRexecServer(tlsConfig, peers)

}

func runWebServer(peers *transport.Peers, tlsSignature []byte) {

	handshakeHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		peerId, signature, err := crypto.OpenHandshakeMessage("server", r.Body)
		if err != nil {
			log.Printf("Opening handshake message failed: %s", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log.Printf("Got handshake from '%v' with signature '%x'", peerId, signature)

		peers.Update(peerId, signature)

		msg, err := crypto.BuildHandshakeMessage("server", peerId, tlsSignature)
		if err != nil {
			log.Printf("BuildHandshakeMessage failed: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(msg)
	}

	http.HandleFunc("/api/v1/handshake", handshakeHandler)
	http.ListenAndServe("localhost:9322", nil)
}

func runRexecServer(tlsConfig *tls.Config, peers *transport.Peers) {
	var listener net.Listener

	listener, err := tls.Listen("tcp", "localhost:9323", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	authenticator := func(conn net.Conn) error {
		return transport.SignatureAuthenticator(conn, peers)
	}

	tl, err := spdy.NewTransportListener(listener, authenticator)
	if err != nil {
		log.Fatal(err)
	}

	for {
		t, err := tl.AcceptTransport()
		if err != nil {
			log.Print(err)
			break
		}

		go func() {
			for {
				receiver, err := t.WaitReceiveChannel()
				if err != nil {
					log.Print(err)
					break
				}

				go func() {
					for {
						command := &RemoteCommand{}
						err := receiver.Receive(command)
						if err != nil {
							log.Print(err)
							break
						}

						cmd := exec.Command(command.Cmd, command.Args...)
						cmd.Stdout = command.Stdout
						cmd.Stderr = command.Stderr

						stdin, err := cmd.StdinPipe()
						if err != nil {
							log.Print(err)
							break
						}
						go func() {
							io.Copy(stdin, command.Stdin)
							stdin.Close()
						}()

						res := cmd.Run()
						command.Stdout.Close()
						command.Stderr.Close()
						returnResult := &CommandResponse{}
						if res != nil {
							if exiterr, ok := res.(*exec.ExitError); ok {
								returnResult.Status = exiterr.Sys().(syscall.WaitStatus).ExitStatus()
							} else {
								log.Print(res)
								returnResult.Status = 10
							}
						}

						err = command.StatusChan.Send(returnResult)
						if err != nil {
							log.Print(err)
						}
					}
				}()
			}
		}()
	}
}
