package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"strconv"
)

// GenerateRsaKey creates a RSA Public key from an exponent and modulus
func GenerateRsaKey(data []string) (*rsa.PublicKey, error) {
	n := new(big.Int)
	n.SetString(data[0], 16)

	e, err := strconv.ParseInt(data[1], 16, 0)
	if err != nil {
		return nil, err
	}

	key := new(rsa.PublicKey)
	key.E = int(e)
	key.N = n

	return key, nil
}

// EncryptRsa encrypts a string using the provided key
func EncryptRsa(msg string, key *rsa.PublicKey) (string, error) {
	cipher, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(msg))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipher), nil
}
