package io

import (
	"hdwg3/md"
)

type IOS interface {
	StoreKey(passphrase string, key *md.Xtd, params ...interface{}) error
	LoadKey(passphrase string, params ...interface{}) (*md.Xtd, error)
}
