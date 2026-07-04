package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
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
	cipher, err := encryptPKCS1v15(key, []byte(msg))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipher), nil
}

// We need our own  legacy PKCS#1 v1.5 public encryption for Deco’s 512-bit key
// because starting with Golang 1.24 rsa.EncryptPKCS1v15() is rejecting 512-bit keys
func encryptPKCS1v15(key *rsa.PublicKey, msg []byte) ([]byte, error) {
	if key == nil || key.N == nil {
		return nil, errors.New("invalid RSA public key")
	}

	k := (key.N.BitLen() + 7) / 8
	if len(msg) > k-11 {
		return nil, errors.New("message too long for RSA public key size")
	}

	em := make([]byte, k)
	em[1] = 2
	ps := em[2 : k-len(msg)-1]
	for i := range ps {
		for ps[i] == 0 {
			if _, err := rand.Read(ps[i : i+1]); err != nil {
				return nil, err
			}
		}
	}
	copy(em[k-len(msg):], msg)

	m := new(big.Int).SetBytes(em)
	e := big.NewInt(int64(key.E))
	c := new(big.Int).Exp(m, e, key.N)

	out := c.Bytes()
	if len(out) >= k {
		return out, nil
	}
	padded := make([]byte, k)
	copy(padded[k-len(out):], out)
	return padded, nil
}
