/*
	André R R Costa ** github.com/andrerrcosta2
*/

package hdds

import (
	"fmt"
	"github.com/btcsuite/btcutil/hdkeychain"
	"hdwg3/cpt"
	"hdwg3/tdp"
	"sync"
	"testing"
)

func init() {
	mht = &HTree{
		Key:  rck(0, 0, 0),
		IOS:  MockIOS{},
		Fn:   "mock_fn",
		Pass: "mock_pass",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}
	arc(mht, 0)
	arc(mht, 3)
	arc(mht, 1+hdkeychain.HardenedKeyStart)
	arcrc(mht, 44+hdkeychain.HardenedKeyStart,
		0+hdkeychain.HardenedKeyStart,
		0+hdkeychain.HardenedKeyStart,
		0, 0,
	)
}

const (
	ksz = 32
	csz = 32
)

var (
	mht *HTree
)

type MockIOS struct {
	t *testing.T
}

func (m MockIOS) StoreKey(passphrase string, key *cpt.Xtd, params ...interface{}) error {
	return nil
}

func (m MockIOS) LoadKey(passphrase string, args ...interface{}) (*cpt.Xtd, error) {
	fmt.Printf("LoadKey(passphrase string, args ...interface{}) (*cpt.Xtd, error)\n")
	chn, ok := args[1].(uint32)
	if !ok {
		return nil, fmt.Errorf("invalid load key parameters")
	}
	c, ok := mht.Chn[chn]

	if !ok {
		return nil, fmt.Errorf("Path not found")
	}
	if c.Key == nil {
		return nil, fmt.Errorf("No key found on current path")
	}
	return c.Key, nil
}

func arc(p *HTree, i uint32) {
	p.Chn[i] = &HTree{
		Key:  rck(p.Key.Dep+1, p.Key.Fpt(), i),
		IOS:  MockIOS{},
		Fn:   "mock_fn",
		Pass: "mock_pass",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}
}

func rck(dep byte, fin, chn uint32) *cpt.Xtd {
	key, _ := tdp.Rand(ksz)
	cc, _ := tdp.Rand(csz)
	return &cpt.Xtd{
		Key:   key,
		Cc:    cc,
		Dep:   dep,
		Fin:   fin,
		Chn:   chn,
		IsPvt: true,
	}
}

func arcrc(p *HTree, path ...uint32) {
	c := p
	for _, i := range path {
		if _, ok := c.Chn[i]; !ok {
			arc(c, i)
		}
		c = c.Chn[i]
	}
}
