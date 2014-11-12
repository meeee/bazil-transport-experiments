package crypto

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"code.google.com/p/go.crypto/nacl/box"
)

type KeyPair struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
}

func Seal(message []byte, recipientPubKey *[32]byte, senderPrivKey *[32]byte) ([]byte, *[24]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return []byte{}, &nonce, err
	}

	return box.Seal(nil, message, &nonce, recipientPubKey, senderPrivKey), &nonce, nil
}

func Open(message []byte, nonce *[24]byte, senderPubKey *[32]byte, recipientPrivKey *[32]byte) ([]byte, bool) {
	return box.Open(nil, message, nonce, senderPubKey, recipientPrivKey)
}

func LoadKeyPair(filename string, keyPair *KeyPair) error {
	d, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(d, keyPair)
}

func WriteKeyPair(filename string, keyPair *KeyPair) error {
	d, err := json.Marshal(keyPair)
	if err != nil {
		return err
	}
	// This file contains a private key, only the owner should be able to read it
	return ioutil.WriteFile(filename, d, 0600)
}

func LoadOrCreateKeyPair(filename string) (*KeyPair, error) {
	keyPair := &KeyPair{}

	err := LoadKeyPair(filename, keyPair)

	if err != nil {
		if _, ok := err.(*os.PathError); ok {

			publicKey, privateKey, err := box.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}

			keyPair.PrivateKey = privateKey
			keyPair.PublicKey = publicKey

			if err := WriteKeyPair(filename, keyPair); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return keyPair, nil
}

// In contrast to LoadOrCreateKeyPair, this function gets peer IDs as input, not
// file names
// Returns key pairs in the same order as the provided keyIDs.
func LoadOrCreatePeerKeyPairs(peerIds []string) ([]*KeyPair, error) {
	keyPairs := make([]*KeyPair, len(peerIds))
	for i, peerId := range peerIds {
		filename, err := keyPairPath(peerId)
		if err != nil {
			return nil, err
		}
		pair, err := LoadOrCreateKeyPair(filename)
		if err != nil {
			return nil, err
		}
		keyPairs[i] = pair
	}
	return keyPairs, nil
}

func SealDataForPeer(ownId string, peerId string, data []byte) ([]byte, *[24]byte, error) {
	peerIds := []string{ownId, peerId}

	keyPairs, err := LoadOrCreatePeerKeyPairs(peerIds)
	if err != nil {
		return nil, nil, fmt.Errorf("SealDataForPeer: LoadOrCreatePeerKeyPairs failed: %v", err)
	}

	return Seal(data, keyPairs[1].PublicKey, keyPairs[0].PrivateKey)
}

func OpenDataFromPeer(ownId string, peerId string, sealed []byte, nonce *[24]byte) ([]byte, error) {
	peerIds := []string{ownId, peerId}

	keyPairs, err := LoadOrCreatePeerKeyPairs(peerIds)
	if err != nil {
		return nil, err
	}

	data, ok := Open(sealed, nonce, keyPairs[1].PublicKey, keyPairs[0].PrivateKey)
	if !ok {
		return nil, errors.New("crypto.OpenDataFromPeer: Failed to open sealed message")
	}

	return data, nil
}

func keyPairPath(peerId string) (string, error) {
	if !peerIdAllowed(peerId) {
		return "", errors.New(
			fmt.Sprintf("crypto.keyPairPath: peer id contains not allowed value: '%v'", peerId))
	}
	return fmt.Sprintf("certs/%s.nacl.json", peerId), nil
}

func peerIdAllowed(peerId string) bool {
	match, _ := regexp.MatchString("^[a-zA-Z0-9]+$", peerId)
	return match
}
