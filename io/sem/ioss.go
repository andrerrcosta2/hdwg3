// Created by André R R Costa ** github.com/andrerrcosta2
// File: ioss.go
// Date:
// Description:
// --------------------------------------------------------------

package sem

type IOSS interface {
	StoreQuery(args ...interface{}) (string, error)
	LoadQuery(args ...interface{}) (string, error)
}
