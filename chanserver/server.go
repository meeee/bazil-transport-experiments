package main

import (
	"crypto/tls"
	"encoding/json"
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
	crypto.Experiment()

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

	go runWebServer()
	runRexecServer(tlsConfig)

}

func handshakeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	type HandshakeMessage struct {
		Nonce, SealedCertSignature []byte
	}

	dec := json.NewDecoder(r.Body)
	var m HandshakeMessage
	if err := dec.Decode(&m); err != nil {
		log.Printf("JSON decoding of message failed: %s", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Printf("Got message: %v", m)
	log.Printf("Nonce: %s", m.Nonce)
	log.Printf("Sig: %s", m.SealedCertSignature)
	w.Write([]byte(":)"))
	// body := ioutil.ReadAll(r.Body)

}

func runWebServer() {
	http.HandleFunc("/api/v1/handshake", handshakeHandler)
	http.ListenAndServe("localhost:9322", nil)
}

func runRexecServer(tlsConfig *tls.Config) {
	var listener net.Listener

	listener, err := tls.Listen("tcp", "localhost:9323", tlsConfig)
	if err != nil {
		log.Fatal(err)
	}

	tl, err := spdy.NewTransportListener(listener, transport.TestAuthenticator)
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
