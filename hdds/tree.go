package hdds

import (
	"fmt"
	"hdwg3/io"
	"hdwg3/md"
	"os"
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

func (tree *HTree) Child(i uint32) (*HTree, error) {
	tree.mtx.Lock()
	defer tree.mtx.Unlock()

	if child, exists := tree.Chn[i]; exists {
		return child, nil
	}

	filename := fmt.Sprintf("key-%d-%d.dat", tree.Key.Dep+1, i)
	childKey, err := tree.IOS.LoadKey(filename, tree.Pass)
	if err == nil {
		child := NewHTree(childKey, tree.IOS, tree.Fn, tree.Pass)
		tree.Chn[i] = child
		return child, nil
	}

	if os.IsNotExist(err) {
		return nil, fmt.Errorf("child key not found at depth %d, index %d", tree.Key.Dep+1, i)
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
