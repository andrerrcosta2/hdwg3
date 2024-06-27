package io

import (
	"fmt"
	"hdwg3/md"
	"hdwg3/pkc"
	"os"
)

type FileKeyStore struct{}

func (f *FileKeyStore) StoreKey(key *md.Xtd, passphrase string) error {
	filename := fmt.Sprintf("key-%d-%d.dat", key.Depth, key.ChildNumber)

	data, err := pkc.SerK(key)
	if err != nil {
		return err
	}

	encryptedData, err := pkc.Encr(data, passphrase)
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

	data, err := pkc.Decr(encryptedData, passphrase)
	if err != nil {
		return nil, err
	}

	return pkc.DesK(data)
}
