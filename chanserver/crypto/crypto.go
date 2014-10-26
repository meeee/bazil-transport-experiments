package crypto

import (
	"crypto/rand"
	"log"

	"code.google.com/p/go.crypto/nacl/box"
)

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
	box, nonce, err := seal(message, publicKey2, privateKey1)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Sealed box: %x Nonce: %x", box, nonce)

	plain, ok := open(box, nonce, publicKey1, privateKey2)
	if !ok {
		log.Fatal(err)
	}

	log.Printf("Plain: %s", plain)

}

func seal(message []byte, recipientPubKey *[32]byte, senderPrivKey *[32]byte) ([]byte, *[24]byte, error) {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return []byte{}, &nonce, err
	}

	return box.Seal(nil, message, &nonce, recipientPubKey, senderPrivKey), &nonce, nil
}

func open(message []byte, nonce *[24]byte, senderPubKey *[32]byte, recipientPrivKey *[32]byte) ([]byte, bool) {
	return box.Open(nil, message, nonce, senderPubKey, recipientPrivKey)
}
