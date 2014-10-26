package crypto

import (
	"bytes"
	"encoding/json"
	"io"
)

type handshakeMessage struct {
	Nonce               *[24]byte
	SealedCertSignature []byte
	PeerId              string
}

func BuildHandshakeMessage(ownId string, peerId string, signature []byte) (io.Reader, error) {
	sealed, nonce, err := SealDataForPeer(ownId, peerId, signature)
	if err != nil {
		return nil, err
	}

	msg := handshakeMessage{nonce, sealed, ownId}

	j, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(j), nil
}

func OpenHandshakeMessage(ownId string, peerId string, data io.Reader) (*handshakeMessage, error) {
	dec := json.NewDecoder(data)

	var m handshakeMessage
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}

	return &m, nil
}
