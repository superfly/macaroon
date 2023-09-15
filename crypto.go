package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceLen          = 12
	EncryptionKeySize = 32
)

type SigningKey []byte
type EncryptionKey []byte

func NewSigningKey() SigningKey {
	return SigningKey(rbuf(sha256.Size))
}

func NewEncryptionKey() EncryptionKey {
	return EncryptionKey(rbuf(EncryptionKeySize))
}

func seal(key EncryptionKey, buf []byte) []byte {
	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		log.Panicf("seal: bad input for key: %s", err)
	}

	nonce := sealNonce()

	rct := aead.Seal(nil, nonce, buf, nil)

	ct := &bytes.Buffer{}
	ct.Write(nonce)
	ct.Write(rct)
	return ct.Bytes()
}

func unseal(key EncryptionKey, buf []byte) ([]byte, error) {
	if len(buf) < nonceLen+1 {
		return nil, fmt.Errorf("unseal: malformed input")
	}

	aead, err := chacha20poly1305.New([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("unseal: bad input for key: %s", err)
	}

	nonce := buf[:nonceLen]
	ct := buf[nonceLen:]

	return aead.Open(nil, nonce, ct, nil)
}

func digest(buf []byte) []byte {
	hash := sha256.New()
	hash.Write(buf)
	return hash.Sum(nil)
}

func sign(key SigningKey, buf []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(buf)
	return mac.Sum(nil)
}

func sealNonce() []byte {
	return rbuf(nonceLen)
}

func rbuf(sz int) []byte {
	buf := make([]byte, sz)
	if n, err := rand.Read(buf); n != sz || err != nil {
		log.Panicf("crypto random failed: %d read of %d: err: %s", n, sz, err)
	}

	return buf
}
