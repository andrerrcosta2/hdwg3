package io

import (
	"fmt"
	"hdwg3/md"
	"hdwg3/pck"
	"os"
)

type FileKeyStore struct{}

func (f *FileKeyStore) StoreKey(key *md.Xtd, passphrase string) error {
	filename := fmt.Sprintf("key-%d-%d.dat", key.Dep, key.ChildNumber)

	data, err := pck.SerK(key)
	if err != nil {
		return err
	}

	encryptedData, err := pck.Encr(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encryptedData, 0644)
}

func (f *FileKeyStore) LoadKey(filename, passphrase string) (*md.Xtd, error) {
	encryptedData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := pck.Decr(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	return pck.DesK(data)
}
