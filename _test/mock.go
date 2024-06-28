package _test

import (
	"hdwg3/hdds"
	"hdwg3/io"
	"hdwg3/md"
	"sync"
)

type MockIOS struct{}

func (m MockIOS) StoreKey(passphrase string, key *md.Xtd, args ...interface{}) error {
	return nil
}

func (m MockIOS) LoadKey(passphrase string, args ...interface{}) (*md.Xtd, error) {
	return &md.Xtd{
		Key:   []byte{},
		Cc:    []byte{},
		Dep:   0,
		Fin:   0,
		Chn:   0,
		IsPvt: true,
	}, nil
}

type MockHTree struct {
	Key  *md.Xtd
	IOS  io.IOS
	Fn   string
	Pass string
	Chn  map[uint32]*hdds.HTree
	mtx  sync.Mutex
}
