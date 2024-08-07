/*
	André R R Costa ** github.com/andrerrcosta2
*/

package io

import (
	"github.com/andrerrcosta2/hdwg3/cpt"
	"github.com/andrerrcosta2/hdwg3/io/sem"
	"os"
	"sync"
)

type FileKeyStore struct {
	sem sem.IOSS
	mtx sync.Mutex
}

func (f *FileKeyStore) StoreKey(passphrase string, key *cpt.Xtd, args ...interface{}) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	fn, err := f.sem.StoreQuery(args)
	if err != nil {
		return err
	}

	data, err := cpt.SerK(key)
	if err != nil {
		return err
	}

	enc, err := cpt.Encr(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(fn, enc, 0644)
}

func (f *FileKeyStore) LoadKey(passphrase string, args ...interface{}) (*cpt.Xtd, error) {
	filename, err := f.sem.LoadQuery(args)
	if err != nil {
		return nil, err
	}

	enc, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data, err := cpt.Decr(enc, passphrase)
	if err != nil {

		return nil, err
	}

	return cpt.DesK(data)
}
