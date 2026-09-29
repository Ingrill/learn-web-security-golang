package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128
const (
	memoryKiB   = 19 * 1024
	iterations  = 2
	parallelism = 1
	keyLength   = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, keyLength)
	argonString := encodeArgon2idHash(argon2idHash{
		version:     argon2.Version,
		memoryKiB:   19 * 1024,
		iterations:  2,
		parallelism: 1,
		salt:        salt,
		derivedKey:  derivedKey,
	})
	return argonString, nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	legacyHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], legacyHash) == 1
	}
	expectedHash, ok := parseArgon2idHash(encodedHash)
	if !ok {
		return false
	}
	if expectedHash.version != argon2.Version {
		return false
	}
	candidateHash := argon2.IDKey([]byte(password), expectedHash.salt, expectedHash.iterations, expectedHash.memoryKiB, expectedHash.parallelism, uint32(len(expectedHash.derivedKey)))
	return subtle.ConstantTimeCompare(expectedHash.derivedKey, candidateHash) == 1
}

func NeedsRehash(encodedString string) bool {
	_, ok := decodeLegacyHash(encodedString)
	if ok {
		return true
	}
	cache, ok := parseArgon2idHash(encodedString)
	if !ok {
		return false
	}
	if cache.version != argon2.Version ||
		cache.iterations != iterations ||
		cache.memoryKiB != memoryKiB ||
		cache.parallelism != parallelism ||
		len(cache.derivedKey) != keyLength {
		return true
	}
	return false
}
