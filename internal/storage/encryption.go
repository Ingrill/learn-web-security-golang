package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func encrypt(
	plaintext []byte,
	key [32]byte,
	randomSource io.Reader,
) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(randomSource, nonce); err != nil {
		return EncryptedPayload{}, err
	}

	sealed := aead.Seal(nil, nonce, plaintext, nil)
	splitIndex := len(sealed) - aead.Overhead()

	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[splitIndex:],
		Ciphertext: sealed[:splitIndex],
	}, nil
}

func Encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	splitIndex := len(sealed) - aead.Overhead()
	return EncryptedPayload{
		Nonce:      nonce,
		AuthTag:    sealed[splitIndex:],
		Ciphertext: sealed[:splitIndex]}, nil
}

func Decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != 12 || len(payload.AuthTag) != 16 {
		return []byte{}, fmt.Errorf("invalid nonce or authentication tag length")
	}
	sealed := make([]byte, 0, len(payload.AuthTag)+len(payload.Ciphertext))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return []byte{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	decrypted, err := aead.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return []byte{}, err
	}
	return decrypted, nil
}
