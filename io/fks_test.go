package io

import (
	"bou.ke/monkey"
	"bytes"
	"errors"
	"fmt"
	"github.com/stretchr/testify/mock"
	"hdwg3/cpt"
	"os"
	"testing"
)

// TestStoreKeySuccess
func TestStoreKeySuccess(t *testing.T) {

	mckFioss := new(mockIoss)
	fks := &FileKeyStore{
		sem: mckFioss,
	}

	mckFioss.On("StoreQuery", mock.Anything).Return("/path/to/file", nil)

	monkey.Patch(cpt.SerK, func(key *cpt.Xtd) ([]byte, error) {
		return []byte("serialized_key"), nil
	})
	defer monkey.Unpatch(cpt.SerK)

	monkey.Patch(cpt.Encr, func(data []byte, passphrase string) ([]byte, error) {
		return []byte("encrypted_data"), nil
	})
	defer monkey.Unpatch(cpt.Encr)

	monkey.Patch(cpt.DesK, func(data []byte) (*cpt.Xtd, error) {
		return rck(0, 0, 0), nil
	})
	defer monkey.Unpatch(cpt.DesK)

	monkey.Patch(os.WriteFile, func(fn string, dat []byte, perm os.FileMode) error {

		isDat := bytes.Equal(dat, []byte("encrypted_data"))
		if fn == "/path/to/file" && bytes.Equal(dat, []byte("encrypted_data")) {
			fmt.Printf("sdat: %t\n", isDat)
			return nil
		}
		return os.ErrNotExist
	})
	defer monkey.Unpatch(os.WriteFile)

	monkey.Patch(os.ReadFile, func(fn string) ([]byte, error) {
		if fn == "/path/to/file" {
			return []byte{}, nil
		}
		return nil, os.ErrNotExist
	})
	defer monkey.Unpatch(os.ReadFile)

	err := fks.StoreKey("thisisafixedpassphrase1234567890", rck(2, 0x00, 0), 44, 0)
	if err != nil {
		t.Errorf("StoreKey failed: %v", err)
	}
}

// TestStoreKeyError
func TestStoreKeyError(t *testing.T) {

	mckFioss := new(mockIoss)
	fks := &FileKeyStore{
		sem: mckFioss,
	}

	mckFioss.On("StoreQuery", mock.Anything).Return("", errors.New("storequery failed"))

	monkey.Patch(cpt.SerK, func(key *cpt.Xtd) ([]byte, error) {
		return []byte("serialized_key"), nil
	})
	defer monkey.Unpatch(cpt.SerK)

	monkey.Patch(cpt.Encr, func(data []byte, passphrase string) ([]byte, error) {
		return []byte("encrypted_data"), nil
	})
	defer monkey.Unpatch(cpt.Encr)

	monkey.Patch(cpt.DesK, func(data []byte) (*cpt.Xtd, error) {
		return rck(0, 0, 0), nil
	})
	defer monkey.Unpatch(cpt.DesK)

	monkey.Patch(os.WriteFile, func(fn string, dat []byte, perm os.FileMode) error {

		isDat := bytes.Equal(dat, []byte("encrypted_data"))
		if fn == "/path/to/file" && bytes.Equal(dat, []byte("encrypted_data")) {
			fmt.Printf("sdat: %t\n", isDat)
			return nil
		}
		return os.ErrNotExist
	})
	defer monkey.Unpatch(os.WriteFile)

	monkey.Patch(os.ReadFile, func(fn string) ([]byte, error) {
		if fn == "/path/to/file" {
			return []byte{}, nil
		}
		return nil, os.ErrNotExist
	})
	defer monkey.Unpatch(os.ReadFile)

	err := fks.StoreKey("passphrase", rck(0, 0, 0), 44, 0)
	if err == nil {
		t.Errorf("Expected StoreKey to fail but got no error")
	}
}

// TestLoadKeySuccess
func TestLoadKeySuccess(t *testing.T) {

	mckFioss := new(mockIoss)
	fks := &FileKeyStore{
		sem: mckFioss,
	}

	mckFioss.On("LoadQuery", mock.Anything).Return("/path/to/file", nil)

	monkey.Patch(cpt.SerK, func(key *cpt.Xtd) ([]byte, error) {
		return []byte("serialized_key"), nil
	})
	defer monkey.Unpatch(cpt.SerK)

	monkey.Patch(cpt.DesK, func(data []byte) (*cpt.Xtd, error) {
		return rck(0, 0, 0), nil
	})
	defer monkey.Unpatch(cpt.DesK)

	monkey.Patch(os.WriteFile, func(fn string, dat []byte, perm os.FileMode) error {

		isDat := bytes.Equal(dat, []byte("encrypted_data"))
		if fn == "/path/to/file" && bytes.Equal(dat, []byte("encrypted_data")) {
			fmt.Printf("sdat: %t\n", isDat)
			return nil
		}
		return os.ErrNotExist
	})
	defer monkey.Unpatch(os.WriteFile)

	monkey.Patch(os.ReadFile, func(fn string) ([]byte, error) {
		if fn == "/path/to/file" {
			ctxt, _ := cpt.Encr([]byte("encrypted_data"), "thisisafixedpassphrase1234567890")
			fmt.Printf("Encrypted ctxt: %x\n", ctxt)
			return ctxt, nil
		}
		return nil, os.ErrNotExist
	})
	defer monkey.Unpatch(os.ReadFile)

	_, err := fks.LoadKey("thisisafixedpassphrase1234567890", 44, 0)
	if err != nil {
		t.Errorf("LoadKey failed: %v", err)
	}

	mckFioss.AssertExpectations(t)
}

// TestLoadKeyError
func TestLoadKeyError(t *testing.T) {

	mckFioss := new(mockIoss)
	fks := &FileKeyStore{
		sem: mckFioss,
	}

	// Should get an error
	mckFioss.On("LoadQuery", mock.Anything).Return("", errors.New("loadquery failed"))

	monkey.Patch(cpt.SerK, func(key *cpt.Xtd) ([]byte, error) {
		return []byte("serialized_key"), nil
	})
	defer monkey.Unpatch(cpt.SerK)

	monkey.Patch(cpt.DesK, func(data []byte) (*cpt.Xtd, error) {
		return rck(0, 0, 0), nil
	})
	defer monkey.Unpatch(cpt.DesK)

	monkey.Patch(os.WriteFile, func(fn string, dat []byte, perm os.FileMode) error {

		isDat := bytes.Equal(dat, []byte("encrypted_data"))
		if fn == "/path/to/file" && bytes.Equal(dat, []byte("encrypted_data")) {
			fmt.Printf("sdat: %t\n", isDat)
			return nil
		}
		return os.ErrNotExist
	})
	defer monkey.Unpatch(os.WriteFile)

	monkey.Patch(os.ReadFile, func(fn string) ([]byte, error) {
		if fn == "/path/to/file" {
			return []byte{}, nil
		}
		return nil, os.ErrNotExist
	})
	defer monkey.Unpatch(os.ReadFile)

	_, err := fks.LoadKey("passphrase", "args")
	if err == nil {
		t.Errorf("Expected LoadKey to fail but got no error")
	}

	mckFioss.AssertExpectations(t)
}
