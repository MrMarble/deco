package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
)

// AESKey Holds the key and initialitation vector for aes encrypting
type AESKey struct {
	Key []byte
	Iv  []byte
}

var (
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")

	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")

	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)

func init() {
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("cannot seed math/rand package with cryptographically secure random number generator")
	}
	rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
}

// GenerateAESKey generates a new AESKey
func GenerateAESKey() *AESKey {
	key := []byte(fmt.Sprintf("%016d", rand.Int63n(1e16)))
	iv := []byte(fmt.Sprintf("%016d", rand.Int63n(1e16)))

	return &AESKey{Key: key, Iv: iv}
}

// AES256Encrypt encrypt a string using the provided key
func AES256Encrypt(plaintext string, key AESKey) (string, error) {
	bPlaintext, err := pkcs7Padding([]byte(plaintext), aes.BlockSize)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, key.Iv)
	mode.CryptBlocks(ciphertext, bPlaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// AES256Decrypt decrypt a string using the provided key
func AES256Decrypt(encrypted string, key AESKey) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil || len(cipherText) < aes.BlockSize {
		return "", err
	}

	block, err := aes.NewCipher(key.Key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, key.Iv)
	mode.CryptBlocks(cipherText, cipherText)
	cipherText, err = pkcs7Unpadding(cipherText, aes.BlockSize)
	return string(cipherText), err
}

func pkcs7Padding(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpadding validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpadding(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}
