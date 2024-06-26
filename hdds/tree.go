package hdds

import (
	"fmt"
	"hdwg3/io"
	"hdwg3/md"
	"sync"
)

type HTree struct {
	Key  *md.Xtd
	IOS  io.IOS
	Fn   string
	Pass string
	Chn  map[uint32]*HTree
	mtx  sync.Mutex
}

func NewHTree(key *md.Xtd, ios io.IOS, filename, pass string) *HTree {
	return &HTree{
		Key:  key,
		IOS:  ios,
		Fn:   filename,
		Pass: pass,
		Chn:  make(map[uint32]*HTree),
	}
}

func (tree *HTree) GetChild(index uint32) (*HTree, error) {
	tree.mtx.Lock()
	defer tree.mtx.Unlock()

	if child, exists := tree.Chn[index]; exists {
		return child, nil
	}

	childKey, err := tree.Key.Child(index)
	if err != nil {
		return nil, err
	}

	child := NewHTree(childKey, tree.IOS, tree.Fn, tree.Pass)
	tree.Chn[index] = child

	// Optionally store the child key to persistent storage
	err = tree.IOS.StoreKey(childKey, fmt.Sprintf("%s-%d", tree.Fn, index), tree.Pass)
	if err != nil {
		return nil, err
	}

	return child, nil
}
