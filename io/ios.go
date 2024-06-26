package io

import "hdwg3/md"

type IOS interface {
	StoreKey(key *md.Xtd, filename, passphrase string) error
	LoadKey(filename, passphrase string) (*md.Xtd, error)
}
