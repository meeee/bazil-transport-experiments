package crypto

import (
	"crypto/rand"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"code.google.com/p/go.crypto/nacl/box"
)

type KeyPair struct {
	PublicKey  *[32]byte
	PrivateKey *[32]byte
}

func Experiment() {
	publicKey1, privateKey1, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	publicKey2, privateKey2, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	message := []byte("Hello :)")
	box, nonce, err := Seal(message, publicKey2, privateKey1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Sealed box: %x Nonce: %x", box, nonce)

	plain, ok := Open(box, nonce, publicKey1, privateKey2)
	if !ok {
		log.Fatal(err)
	}

	log.Printf("Plain: %s", plain)

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
