package _test

import (
	"hdwg3/cpt"
	"hdwg3/hdds"
	"hdwg3/io"
	"sync"
)

type MockIOS struct{}

func (m MockIOS) StoreKey(passphrase string, key *cpt.Xtd, args ...interface{}) error {
	return nil
}

func (m MockIOS) LoadKey(passphrase string, args ...interface{}) (*cpt.Xtd, error) {
	return &cpt.Xtd{
		Key:   []byte{},
		Cc:    []byte{},
		Dep:   0,
		Fin:   0,
		Chn:   0,
		IsPvt: true,
	}, nil
}

type MockHTree struct {
	Key  *cpt.Xtd
	IOS  io.IOS
	Fn   string
	Pass string
	Chn  map[uint32]*hdds.HTree
	mtx  sync.Mutex
}
