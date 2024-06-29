// Created by André R R Costa ** github.com/andrerrcosta2
// File: tree_test.go
// Date:
// Description:
// --------------------------------------------------------------

package hdds

import (
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/hdkeychain"
	"hdwg3/cpt"
	"regexp"
	"testing"
)

func TestChd(t *testing.T) {
	tcs := []struct {
		ind uint32
		exp error
	}{
		{ind: 0, exp: nil},
		{ind: 44 + hdkeychain.HardenedKeyStart, exp: nil},
		{ind: 1 + hdkeychain.HardenedKeyStart, exp: nil},
	}

	for i, tc := range tcs {
		chd, err := mht.Child(tc.ind)
		if tc.exp != nil {
			if err == nil || err.Error() != tc.exp.Error() {
				t.Errorf("Child(%v) unexpected error: \nerr: %v, \nexp: %v", tc.ind, err, tc.exp)
			}
		} else {
			if err != nil {
				t.Errorf("Child(%d) unexpected error: \nerr %v, \nexp nil", tc.ind, err)
			}
		}
		fmt.Printf("Child(%d): %+v\n", i, chd)
	}
}

func TestGCoC(t *testing.T) {
	tcs := []struct {
		ind uint32
		exp error
	}{
		{ind: 0, exp: nil},
	}

	for _, tc := range tcs {
		_, err := mht.GCoC(tc.ind)
		if !errors.Is(err, tc.exp) {
			t.Errorf("CreateChild(%d) unexpected error: \nerr %v, \nexo %v", tc.ind, err, tc.exp)
		}
	}
}

func TestKeyAt(t *testing.T) {
	tcs := []struct {
		path []uint32
		exp  error
	}{
		{path: []uint32{0, 0, 1}, exp: fmt.Errorf("Path not found")},
		{path: []uint32{0, 44 + hdkeychain.HardenedKeyStart}, exp: nil},
	}

	for _, tc := range tcs {
		_, err := mht.KeyAt(tc.path)
		if tc.exp != nil {
			if err == nil || err.Error() != tc.exp.Error() {
				t.Errorf("KeyAt(%v) unexpected error: \nerr: %v, \nexp: %v", tc.path, err, tc.exp)
			}
		} else {
			if err != nil {
				t.Errorf("KeyAt(%v) unexpected error: \nerr: %v, \nexp: nil", tc.path, err)
			}
		}
	}
}

func TestAddr(t *testing.T) {
	tcs := []struct {
		path string
		exp  *regexp.Regexp
	}{
		{path: "m/44'/0'/0'/0/0", exp: regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$`)},
	}

	for _, tc := range tcs {
		addr, err := mht.Addr(tc.path)
		if err != nil {
			fmt.Printf("Addr(%s) error: %v", tc.path, err)
		}

		if !tc.exp.MatchString(addr) {
			t.Errorf("Addr(%s) unexpected address format: \naddr: %s", tc.path, addr)
		}
	}
}

func TestKd(t *testing.T) {
	tcs := []struct {
		path   string
		expXtd *cpt.Xtd
		expErr error
	}{
		{path: "m/44'/0'/0'/0/0", expXtd: &cpt.Xtd{}, expErr: nil},
	}

	for _, tc := range tcs {
		_, err := mht.kd(tc.path)
		if !errors.Is(err, tc.expErr) {
			t.Errorf("kd(%s) returned unexpected error: got %v, want %v", tc.path, err, tc.expErr)
		}
	}
}

func TestHTree(t *testing.T) {
	t.Run("Child", TestChd)
	t.Run("CreateChild", TestGCoC)
	t.Run("KeyAt", TestKeyAt)
	t.Run("Addr", TestAddr)
	t.Run("Kd", TestKd)
}
