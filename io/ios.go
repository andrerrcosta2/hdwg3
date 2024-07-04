/*
	André R R Costa ** github.com/andrerrcosta2
*/

package io

import (
	"github.com/andrerrcosta2/hdwg3/cpt"
)

type IOS interface {
	StoreKey(passphrase string, key *cpt.Xtd, params ...interface{}) error
	LoadKey(passphrase string, params ...interface{}) (*cpt.Xtd, error)
}
