package io

import (
	"hdwg3/io/fioss"
	"hdwg3/md"
	"hdwg3/pck"
	"os"
)

type FileKeyStore struct {
	sem fioss.Fioss
}

func (f *FileKeyStore) StoreKey(passphrase string, key *md.Xtd, args ...interface{}) error {
	fn, err := f.sem.StoreQuery(args)
	if err != nil {
		return err
	}

	data, err := pck.SerK(key)
	if err != nil {
		return err
	}

	enc, err := pck.Encr(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(fn, enc, 0644)
}

func (f *FileKeyStore) LoadKey(passphrase string, args ...interface{}) (*md.Xtd, error) {
	filename, err := f.sem.LoadQuery(args)
	if err != nil {
		return nil, err
	}

	enc, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := pck.Decr(enc, passphrase)
	if err != nil {

		return nil, err
	}

	return pck.DesK(data)
}
