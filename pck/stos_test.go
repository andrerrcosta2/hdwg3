package pck

import (
	"bytes"
	"crypto/rand"
	"hdwg3/md"
	"testing"
)

func TestSerAndDesXtd(t *testing.T) {
	xtd := &md.Xtd{
		Key:       []byte{0x01, 0x02, 0x03, 0x04},
		Cc:        []byte{0x05, 0x06, 0x07, 0x08},
		Dep:       0,
		Fin:       0,
		Chn:       0,
		IsPrivate: true,
	}

	ser, err := SerK(xtd)
	if err != nil {
		t.Fatalf("Failed on serializing xtd: %v", err)
	}

	des, err := DesK(ser)
	if err != nil {
		t.Fatalf("Failed to deserialize xtd: %v", err)
	}

	if !bytes.Equal(xtd.Key, des.Key) ||
		!bytes.Equal(xtd.Cc, des.Cc) ||
		xtd.Dep != des.Dep ||
		xtd.Fin != des.Fin ||
		xtd.Chn != des.Chn ||
		xtd.IsPrivate != des.IsPrivate {
		t.Errorf("Deserialized xtd doesn't match")
	}
}

func TestEncAndDec(t *testing.T) {
	data := []byte("this is a test data")
	// random pass
	pass := make([]byte, 32)
	if _, err := rand.Read(pass); err != nil {
		t.Fatalf("Failed to generate pass: %v", err)
	}

	enc, err := Encr(data, string(pass))
	if err != nil {
		t.Fatalf("Failed on encrypting data: %v", err)
	}

	dec, err := Decr(enc, string(pass))
	if err != nil {
		t.Fatalf("Failed on decrypting data: %v", err)
	}

	if !bytes.Equal(data, dec) {
		t.Errorf("Decrypted data doesnt match")
	}
}

func TestEncAndDecWithFixedPassphrase(t *testing.T) {
	data := []byte("this is a test data")
	pass := "thisisafixedpassphrase"

	enc, err := Encr(data, pass)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	if bytes.Equal(data, enc) {
		t.Errorf("Encrypted data is the same than original")
	}

	dec, err := Decr(enc, pass)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(data, dec) {
		t.Errorf("Decrypted data does not match with original")
	}
}
