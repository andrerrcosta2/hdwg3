// Created by André R R Costa ** github.com/andrerrcosta2
// File: fioss.go
// Date:
// Description:
// --------------------------------------------------------------

package fioss

import "fmt"

type Fioss struct {
}

func (f Fioss) StoreQuery(args ...interface{}) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("insufficient parameters to construct query")
	}
	dep, ok1 := args[0].(byte)
	chn, ok2 := args[1].(uint32)
	if !ok1 || !ok2 {
		return "", fmt.Errorf("invalid parameters")
	}

	return fmt.Sprintf("tdp-%d-%d.dat", dep, chn), nil
}

func (f Fioss) LoadQuery(args ...interface{}) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("insufficient parameters to construct query")
	}
	dep, ok1 := args[0].(byte)
	chn, ok2 := args[1].(uint32)
	if !ok1 || !ok2 {
		return "", fmt.Errorf("invalid parameters")
	}

	return fmt.Sprintf("tdp-%d-%d.dat", dep, chn), nil
}

func New() Fioss {
	return Fioss{}
}
