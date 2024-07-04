/*
	André R R Costa ** github.com/andrerrcosta2
*/

package pck

import (
	"crypto/sha512"
	"encoding/hex"
	"github.com/andrerrcosta2/hdwg3/md"
	"golang.org/x/crypto/pbkdf2"
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
			expMK:   "b4f1b7de11a76199753052bcda155f1b5f2332c52b4f73ca33099dfb136fee92",
			expCC:   "d2b92180421d55e5483f13e4124c69fb81d5ddcf55cdec0778f3b250b2ad3b36",
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
			exp:  "94fa60b4eb901c27915ed7a45e8d140e7c2b675133410ddc95fad5fcb3ab92c618f2c4aff4a37fcbd1b321e44cfc07ac93d36240ba7ccb754163cead26268503",
		},
	}

	for _, tc := range tcs {
		res := HmacSHA512(tc.key, tc.data)
		res16 := hex.EncodeToString(res)
		if res16 != tc.exp {
			t.Errorf("Returned hmac %s,\nexp %s", res16, tc.exp)
		}
	}
}
