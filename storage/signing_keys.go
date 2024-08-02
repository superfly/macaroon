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

func (vks VerificationKeys) Add(keys ...macaroon.SigningKey) {
	for _, key := range keys {
		vks[sha256.Sum256(key)] = key
	}
}

func (vks VerificationKeys) get(kid []byte) (macaroon.SigningKey, bool) {
	if len(kid) != keyIDSize {
		return nil, false
	}

	key, ok := vks[keyID(kid)]
	return key, ok
}

type ThirdPartyVerificationKeys map[string][]macaroon.EncryptionKey

func (tpvks ThirdPartyVerificationKeys) Add(location string, keys ...macaroon.EncryptionKey) {
	tpvks[location] = append(tpvks[location], keys...)
}
