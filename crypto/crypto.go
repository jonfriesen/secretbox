package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

// ErrDecryption is a general error on decryption errors
var ErrDecryption = errors.New("could not decrypt message")

// Key is the secret key used to encrypt/decrypt secrets
type Key [32]byte

// Generate randomly creates a 32byte secret key
func (k *Key) Generate() error {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}

	copy(k[:], key[0:32])

	return nil
}

// String returns a string version of the key
func (k *Key) String() string {
	return fmt.Sprintf("%x", k.Bytes())
}

// Encrypt takes a plaintext message in byte slice format and returns an encrypted message.
// This message wraps the nonce into the returned box so its not required during decryption.
func (k *Key) Encrypt(message []byte) ([]byte, error) {
	// check if already encrypted
	if IsBoxedMessage(message) {
		return message, nil
	}

	secretBox, err := k.encrypt(message)
	if err != nil {
		return nil, err
	}

	return secretBox.Dump(), nil
}

func (k *Key) encrypt(message []byte) (*secretBoxedMessage, error) {
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	key := k.Bytes()
	out := secretbox.Seal(nil, message, &nonce, &key)

	return &secretBoxedMessage{
		SchemaVersion: 1,
		Nonce:         nonce,
		Box:           out,
	}, nil
}

// Decrypt receives an encrypted message in the secret box format which includes the Nonce and returns
// the plaintext value decrypted
func (k *Key) Decrypt(message []byte) ([]byte, error) {
	var sb secretBoxedMessage
	err := sb.Load(message)
	if err != nil {
		return nil, err
	}

	return k.decrypt(&sb)
}

func (k *Key) decrypt(sb *secretBoxedMessage) ([]byte, error) {
	key := k.Bytes()
	decrypted, valid := secretbox.Open(nil, sb.Box, &sb.Nonce, &key)
	if !valid {
		return nil, ErrDecryption
	}

	return decrypted, nil
}

// Bytes returns the key in [32]byte form
func (k *Key) Bytes() [32]byte {
	return [32]byte(*k)
}

func generateNonce() ([24]byte, error) {
	var nonce [24]byte

	s := make([]byte, 24)
	_, err := rand.Read(s)
	if err != nil {
		return nonce, err
	}

	copy(nonce[:], s[0:24])

	return nonce, nil
}
