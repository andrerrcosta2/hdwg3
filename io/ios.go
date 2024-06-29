// Created by André R R Costa ** github.com/andrerrcosta2
// File: ios.go
// Date:
// Description:
// --------------------------------------------------------------

package io

import (
	"hdwg3/cpt"
)

type IOS interface {
	StoreKey(passphrase string, key *cpt.Xtd, params ...interface{}) error
	LoadKey(passphrase string, params ...interface{}) (*cpt.Xtd, error)
}
