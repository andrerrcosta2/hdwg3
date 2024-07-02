// André R R Costa *** github.com/andrerrcosta2

package fioss

import (
	"testing"
)

func TestStoreQuery(t *testing.T) {
	fsem := New()

	// Successful StoreQuery
	fn, err := fsem.StoreQuery(byte(1), uint32(100))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	exp := "tdp-1-100.dat"
	if fn != exp {
		t.Errorf("Expected %s, \nreturned: %s\n", exp, fn)
	}

	// StoreQuery with insufficient parameters
	fn, err = fsem.StoreQuery(byte(1))
	if err == nil {
		t.Error("Expected error for insufficient parameters")
	}

	// StoreQuery with invalid parameters
	fn, err = fsem.StoreQuery(byte(1), "invalid")
	if err == nil {
		t.Error("Expected error for invalid parameters")
	}
}

func TestLoadQuery(t *testing.T) {
	fsem := New()

	// Successful LoadQuery
	fn, err := fsem.LoadQuery(byte(2), uint32(200))
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	exp := "tdp-2-200.dat"
	if fn != exp {
		t.Errorf("Expected %s, \nreceive %s\n", exp, fn)
	}

	// LoadQuery with insufficient parameters
	fn, err = fsem.LoadQuery(byte(2))
	if err == nil {
		t.Error("Expected error for insufficient parameters")
	}

	// LoadQuery with invalid parameters
	fn, err = fsem.LoadQuery(byte(2), "invalid")
	if err == nil {
		t.Error("Expected error for invalid parameters")
	}
}
