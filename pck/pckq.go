/*
	André R R Costa ** github.com/andrerrcosta2
*/

package pck

import (
	"crypto/hmac"
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"hdwg3/md"
)

func Seed(m md.Mnmc, passphrase string) []byte {
	return pbkdf2.Key(m.Byte(), []byte("mnm"+passphrase), 2048, 64, sha512.New)
}

func MK(seed []byte, keySpec string) ([]byte, []byte) {
	k := []byte(keySpec)
	i := HmacSHA512(k, seed)
	return i[:32], i[32:]
}

func HSP(h func() hash.Hash, d []byte) []byte {
	hr := h()
	hr.Write(d)
	return hr.Sum(nil)
}

func HmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
