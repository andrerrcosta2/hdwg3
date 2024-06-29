package pck

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
			expectedSeed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		},
	}

	for _, test := range tests {
		seed := Seed(test.mnemonic, test.passphrase)
		seedHex := hex.EncodeToString(seed)
		if seedHex != test.expectedSeed {
			t.Errorf("Expected seed %s, got %s", test.expectedSeed, seedHex)
		}
	}
}

func TestDMaK(t *testing.T) {
	tests := []struct {
		seed    []byte
		keySpec string
		expMK   string
		expCC   string
	}{
		{
			seed:    pbkdf2.Key([]byte("mnemonic"), []byte("mnemonic"), 2048, 64, sha512.New),
			keySpec: "Bitcoin seed",
			expMK:   "33542ed0e02dd7044c3e836416af94db528a73590d60212bdf63044767055116",
			expCC:   "4c2232bd0be96bca95331649fa1e358033af50ed676b33f9f00adb286f868fa5",
		},
	}

	for _, test := range tests {
		mk, cc := MK(test.seed, test.keySpec)
		mk16 := hex.EncodeToString(mk)
		cc16 := hex.EncodeToString(cc)
		if mk16 != test.expMK {
			t.Errorf("Expected master tdp %s, got %s", test.expMK, mk16)
		}
		if cc16 != test.expCC {
			t.Errorf("Expected chain code %s, got %s", test.expCC, cc16)
		}
	}
}

func TestHmacSHA512(t *testing.T) {
	tests := []struct {
		key  []byte
		data []byte
		exp  string
	}{
		{
			key:  []byte("Bitcoin seed"),
			data: []byte("mnemonic"),
			exp:  "deb001bfcf04c95869c312be474da1b8320ada66390c63a8630761c71aaac3cdcc3dcdfc033c45bd440bd023905da0c31604f0695143fba30eb1c60adb5ea7c3",
		},
	}

	for _, test := range tests {
		res := HmacSHA512(test.key, test.data)
		res16 := hex.EncodeToString(res)
		if res16 != test.exp {
			t.Errorf("Expected %s, got %s", test.exp, res16)
		}
	}
}
