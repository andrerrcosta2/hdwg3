package pkc

import (
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"hdwg3/md"
	"testing"
)

func TestMnmcToSeed(t *testing.T) {
	tests := []struct {
		mnemonic     md.Mnmc
		passphrase   string
		expectedSeed string
	}{
		{
			mnemonic:     *md.NewMnmc("abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"),
			passphrase:   "",
			expectedSeed: "5eb00bbddcf069084889a8ab9155568165f5cdbeb4b9d0c5948a8ef4a3d6d4c7b6c7e57c2e73b4e0f6f8ee7c4d0f29a4a4eab91b8d90ff5a6162f3b3e819b39d",
		},
	}

	for _, test := range tests {
		seed := MnmcToSeed(test.mnemonic, test.passphrase)
		seedHex := hex.EncodeToString(seed)
		if seedHex != test.expectedSeed {
			t.Errorf("Expected seed %s, got %s", test.expectedSeed, seedHex)
		}
	}
}

func TestDMaK(t *testing.T) {
	tests := []struct {
		seed              []byte
		keySpec           string
		expectedMasterKey string
		expectedChainCode string
	}{
		{
			seed:              pbkdf2.Key([]byte("mnemonic"), []byte("mnemonic"), 2048, 64, sha512.New),
			keySpec:           "Bitcoin seed",
			expectedMasterKey: "2fc32c88e7c57bb2079a00c57b01d6a62fd1627e850adf2f31e1b5f8e18c3e3b",
			expectedChainCode: "fa01b0d86d6b6b5cc1bc2c907890c31aebc5b07c5cb5dbcf7d28a79ccfcfb933",
		},
	}

	for _, test := range tests {
		masterKey, chainCode := DMaK(test.seed, test.keySpec)
		masterKeyHex := hex.EncodeToString(masterKey)
		chainCodeHex := hex.EncodeToString(chainCode)
		if masterKeyHex != test.expectedMasterKey {
			t.Errorf("Expected master key %s, got %s", test.expectedMasterKey, masterKeyHex)
		}
		if chainCodeHex != test.expectedChainCode {
			t.Errorf("Expected chain code %s, got %s", test.expectedChainCode, chainCodeHex)
		}
	}
}

func TestHmacSHA512(t *testing.T) {
	tests := []struct {
		key      []byte
		data     []byte
		expected string
	}{
		{
			key:      []byte("Bitcoin seed"),
			data:     []byte("mnemonic"),
			expected: "2fc32c88e7c57bb2079a00c57b01d6a62fd1627e850adf2f31e1b5f8e18c3e3bfa01b0d86d6b6b5cc1bc2c907890c31aebc5b07c5cb5dbcf7d28a79ccfcfb933",
		},
	}

	for _, test := range tests {
		result := hmacSHA512(test.key, test.data)
		resultHex := hex.EncodeToString(result)
		if resultHex != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, resultHex)
		}
	}
}
