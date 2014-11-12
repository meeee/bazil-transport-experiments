# Bazil Transport Experiment

Built for a discussion on the [bazil filesystem](http://bazil.org/doc/), which needs a transport layer.

This experiment uses [docker/libchan](https://github.com/docker/libchan) and authenticates a TLS-encrypted libchan SPDY connection using TLS client and server ceritificates. It assumes both peers know each other's [NaCl](http://godoc.org/golang.org/x/crypto/nacl/box) public keys (shared via local filesystem in this experiment).

The NaCL keys are used to do a handshake via HTTP that exchanges the peers' TLS-certificates' signatures, signed via NaCl (and encrypted, that would not be required, but was easier to do). The signatures are stored in memory and used to verify following TLS-connections on both ends.

The TLS certificates are generated on startup, the NaCl key pairs are generated when first needed and then persisted in the `certs` folder.

The experiment uses libchan's [rexec rexample](https://github.com/docker/libchan/tree/master/examples/rexec) and allows executing a 'remote' shell command including stdin/stderr/stdout passing, which demonstrates libchan's stream / Go channel multiplexing.

## Usage

    go get github.com/meeee/bazil-transport-experiments
    cd src/github.com/meeee/bazil-transport-experiments
    go build server.go
    ./server

In a different shell for the client:

    cd src/github.com/meeee/bazil-transport-experiments/client
    go build client.go
    cd .. # otherwise it doesn't find the NaCl certs
    # execute `ls -l` on the server
    client/client ls -l
