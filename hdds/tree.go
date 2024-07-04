/*
	André R R Costa ** github.com/andrerrcosta2
*/

package hdds

import (
	"crypto/sha256"
	"fmt"
	"github.com/andrerrcosta2/hdwg3/cpt"
	"github.com/andrerrcosta2/hdwg3/io"
	"github.com/andrerrcosta2/hdwg3/pck"
	"github.com/andrerrcosta2/hdwg3/pfx"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
	"golang.org/x/crypto/ripemd160"
	"os"
	"strconv"
	"strings"
	"sync"
)

type HTree struct {
	Key  *cpt.Xtd
	IOS  io.IOS
	Fn   string
	Pass string
	Chn  map[uint32]*HTree
	mtx  sync.Mutex
}

func NewHTree(key *cpt.Xtd, ios io.IOS, filename, pass string) *HTree {
	return &HTree{
		Key:  key,
		IOS:  ios,
		Fn:   filename,
		Pass: pass,
		Chn:  make(map[uint32]*HTree),
	}
}

func (tree *HTree) Child(i uint32) (*HTree, error) {
	tree.mtx.Lock()
	defer tree.mtx.Unlock()

	if c, exists := tree.Chn[i]; exists {
		return c, nil
	}

	ck, err := tree.IOS.LoadKey(tree.Pass, tree.Key.Dep+1, i)
	if err == nil {
		c := NewHTree(ck, tree.IOS, tree.Fn, tree.Pass)
		tree.Chn[i] = c
		return c, nil
	}

	if os.IsNotExist(err) {
		return nil, fmt.Errorf("child tdp not found at depth %d, ind %d", tree.Key.Dep+1, i)
	}

	return nil, err
}

func (tree *HTree) GCoC(i uint32) (*HTree, error) {
	tree.mtx.Lock()
	defer tree.mtx.Unlock()

	if c, ext := tree.Chn[i]; ext {
		return c, nil
	}

	ck, err := tree.IOS.LoadKey(tree.Pass, tree.Key.Dep+1, i)
	if err == nil {
		child := NewHTree(ck, tree.IOS, tree.Fn, tree.Pass)
		tree.Chn[i] = child
		return child, nil
	}

	if os.IsNotExist(err) {
		ck, err = tree.Key.Child(i)
		if err != nil {
			return nil, fmt.Errorf("failed to generate c tdp: %v", err)
		}

		err = tree.IOS.StoreKey(tree.Pass, ck, tree.Key.Dep+1, i)
		if err != nil {
			return nil, fmt.Errorf("failed to store c tdp: %v", err)
		}

		chi := NewHTree(ck, tree.IOS, tree.Fn, tree.Pass)
		tree.Chn[i] = chi
		return chi, nil
	}

	return nil, err
}

func (tree *HTree) KeyAt(path []uint32) (*HTree, error) {
	current := tree
	var err error

	for _, index := range path {
		current, err = current.Child(index)
		if err != nil {
			return nil, err
		}
	}

	return current, nil
}

func (tree *HTree) Addr(path string) (string, error) {
	ck, err := tree.kd(path)

	if err != nil {
		return "", err
	}

	_, pub := btcec.PrivKeyFromBytes(ck.Key)

	// A = RIPEMD160(SHA235(K))
	s256h := pck.HSP(sha256.New, pub.SerializeCompressed())
	pkh := pck.HSP(ripemd160.New, s256h)

	_v := append(pfx.ADDR_V, pkh...)

	h1 := pck.HSP(sha256.New, _v)
	h2 := pck.HSP(sha256.New, h1)

	return base58.Encode(append(_v, h2[:4]...)), nil
}

func (tree *HTree) kd(path string) (*cpt.Xtd, error) {
	k := tree.Key
	cs := strings.Split(path, "/")[1:]

	for _, c := range cs {
		var i uint32
		if strings.HasSuffix(c, "'") {
			// Hardened
			j, err := strconv.Atoi(strings.TrimSuffix(c, "'"))
			if err != nil {
				return nil, err
			}
			i = uint32(j) + hdkeychain.HardenedKeyStart
		} else {
			j, err := strconv.Atoi(c)
			if err != nil {
				return nil, err
			}
			i = uint32(j)
		}

		ck, err := k.Child(i)
		if err != nil {
			return nil, err
		}
		k = ck
	}
	return k, nil
}
