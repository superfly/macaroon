package storage

import (
	"crypto/sha256"

	"github.com/superfly/macaroon"
)

const keyIDSize = sha256.Size

type keyID [keyIDSize]byte

func calculateKeyID(key macaroon.SigningKey) keyID {
	return sha256.Sum256(key)
}

type VerificationKeys map[keyID]macaroon.SigningKey

func (s VerificationKeys) Add(keys ...macaroon.SigningKey) {
	for _, key := range keys {
		s[sha256.Sum256(key)] = key
	}
}

func (s VerificationKeys) get(kid []byte) (macaroon.SigningKey, bool) {
	if len(kid) != keyIDSize {
		return nil, false
	}

	key, ok := s[keyID(kid)]
	return key, ok
}

type ThirdPartyVerificationKeys map[string][]macaroon.EncryptionKey

func (t ThirdPartyVerificationKeys) Add(location string, keys ...macaroon.EncryptionKey) {
	t[location] = append(t[location], keys...)
}
