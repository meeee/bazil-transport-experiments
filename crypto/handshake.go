package crypto

import (
	"encoding/json"
	"io"
)

type handshakeMessage struct {
	Nonce               *[24]byte
	SealedCertSignature []byte
	PeerId              string
}

func BuildHandshakeMessage(ownId string, peerId string, signature []byte) ([]byte, error) {
	sealed, nonce, err := SealDataForPeer(ownId, peerId, signature)
	if err != nil {
		return nil, err
	}

	msg := handshakeMessage{nonce, sealed, ownId}

	j, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return j, nil
}

func OpenHandshakeMessage(ownId string, data io.Reader) (string, []byte, error) {
	dec := json.NewDecoder(data)

	var m handshakeMessage
	if err := dec.Decode(&m); err != nil {
		return "", nil, err
	}

	signature, err := OpenDataFromPeer(ownId, m.PeerId, m.SealedCertSignature, m.Nonce)
	if err != nil {
		return "", nil, err
	}
	return m.PeerId, signature, nil
}
