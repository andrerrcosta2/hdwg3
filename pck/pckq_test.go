// Created by André R R Costa ** github.com/andrerrcosta2
// File: pckq_test.go
// Date:
// Description:
// --------------------------------------------------------------

package pck

import (
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
	"hdwg3/md"
	"testing"
)

func TestMnmcToSeed(t *testing.T) {
	tcs := []struct {
		mnm  md.Mnmc
		pass string
		exp  string
	}{
		{
			mnm:  *md.NewMnmc("abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "about"),
			pass: "",
			exp:  "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		},
	}

	for _, tc := range tcs {
		seed := Seed(tc.mnm, tc.pass)
		s16 := hex.EncodeToString(seed)
		if s16 != tc.exp {
			t.Errorf("Returned seed %s, \nexp %s", s16, tc.exp)
		}
	}
}

func TestDMaK(t *testing.T) {
	tcs := []struct {
		seed    []byte
		keySpec string
		expMK   string
		expCC   string
	}{
		{
			seed:    pbkdf2.Key([]byte("mnm"), []byte("mnm"), 2048, 64, sha512.New),
			keySpec: "Bitcoin seed",
			expMK:   "33542ed0e02dd7044c3e836416af94db528a73590d60212bdf63044767055116",
			expCC:   "4c2232bd0be96bca95331649fa1e358033af50ed676b33f9f00adb286f868fa5",
		},
	}

	for _, tc := range tcs {
		mk, cc := MK(tc.seed, tc.keySpec)
		mk16 := hex.EncodeToString(mk)
		cc16 := hex.EncodeToString(cc)
		if mk16 != tc.expMK {
			t.Errorf("Returned master tdp %s, \nexp %s", mk16, tc.expMK)
		}
		if cc16 != tc.expCC {
			t.Errorf("Returned chain code %s, \nexp %s", cc16, tc.expCC)
		}
	}
}

func TestHmacSHA512(t *testing.T) {
	tcs := []struct {
		key  []byte
		data []byte
		exp  string
	}{
		{
			key:  []byte("Bitcoin seed"),
			data: []byte("mnm"),
			exp:  "deb001bfcf04c95869c312be474da1b8320ada66390c63a8630761c71aaac3cdcc3dcdfc033c45bd440bd023905da0c31604f0695143fba30eb1c60adb5ea7c3",
		},
	}

	for _, tc := range tcs {
		res := HmacSHA512(tc.key, tc.data)
		res16 := hex.EncodeToString(res)
		if res16 != tc.exp {
			t.Errorf("Returned hmac %s, \nexp %s", res16, tc.exp)
		}
	}
}
