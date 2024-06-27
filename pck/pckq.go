package pck

import (
	"crypto/hmac"
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
	"hdwg3/md"
)

func Seed(m md.Mnmc, passphrase string) []byte {
	return pbkdf2.Key(m.Byte(), []byte("mnemonic"+passphrase), 2048, 64, sha512.New)
}

func MK(seed []byte, keySpec string) ([]byte, []byte) {
	k := []byte(keySpec)
	I := hmacSHA512(k, seed)
	return I[:32], I[32:]
}

func hmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
