package io

import (
	"hdwg3/cpt"
)

type IOS interface {
	StoreKey(passphrase string, key *cpt.Xtd, params ...interface{}) error
	LoadKey(passphrase string, params ...interface{}) (*cpt.Xtd, error)
}
