package hdds

import (
	"errors"
	"hdwg3/cpt"
	"sync"
	"testing"
)

type MockIOS struct{}

func (m MockIOS) StoreKey(passphrase string, key *cpt.Xtd, params ...interface{}) error {
	return nil
}

func (m MockIOS) LoadKey(passphrase string, params ...interface{}) (*cpt.Xtd, error) {
	return mockKey, nil
}

var (
	mockKey = &cpt.Xtd{
		Key:   []byte{},
		Cc:    []byte{},
		Dep:   0,
		Fin:   0,
		Chn:   0,
		IsPvt: true,
	}
	mockHTree = &HTree{
		Key:  mockKey,
		IOS:  MockIOS{},
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}
)

// ChildTest tests the Child method of HTree.
func ChildTest(t *testing.T) {
	testCases := []struct {
		index       uint32
		expectedErr error
	}{
		{index: 0, expectedErr: nil},
	}

	for _, tc := range testCases {
		_, err := mockHTree.Child(tc.index)
		if !errors.Is(err, tc.expectedErr) {
			t.Errorf("Child(%d) returned unexpected error: got %v, want %v", tc.index, err, tc.expectedErr)
		}

	}
}

// CreateChildTest tests the CreateChild method of HTree.
func CreateChildTest(t *testing.T) {
	testCases := []struct {
		index       uint32
		expectedErr error
	}{
		{index: 0, expectedErr: nil},
	}

	for _, tc := range testCases {
		_, err := mockHTree.CreateChild(tc.index)
		if !errors.Is(err, tc.expectedErr) {
			t.Errorf("CreateChild(%d) returned unexpected error: got %v, want %v", tc.index, err, tc.expectedErr)
		}
	}
}

// KeyAtTest tests the KeyAt method of HTree.
func KeyAtTest(t *testing.T) {
	testCases := []struct {
		path        []uint32
		expectedErr error
	}{
		{path: []uint32{0, 1, 2}, expectedErr: nil},
	}

	for _, tc := range testCases {
		_, err := mockHTree.KeyAt(tc.path)
		if !errors.Is(err, tc.expectedErr) {
			t.Errorf("KeyAt(%v) returned unexpected error: got %v, want %v", tc.path, err, tc.expectedErr)
		}
	}
}

func AddrTest(t *testing.T) {
	testCases := []struct {
		path     string
		expected string
	}{
		{path: "m/44'/0'/0'/0/0", expected: "expected_address_here"},
	}

	for _, tc := range testCases {
		addr, err := mockHTree.Addr(tc.path)
		if err != nil {
			t.Errorf("Addr(%s) returned error: %v", tc.path, err)
		}

		if addr != tc.expected {
			t.Errorf("Addr(%s) returned unexpected address: got %s, want %s", tc.path, addr, tc.expected)
		}
	}
}

func KdTest(t *testing.T) {
	testCases := []struct {
		path        string
		expectedXtd *cpt.Xtd
		expectedErr error
	}{
		{path: "m/44'/0'/0'/0/0", expectedXtd: &cpt.Xtd{}, expectedErr: nil},
	}

	for _, tc := range testCases {
		_, err := mockHTree.kd(tc.path)
		if !errors.Is(err, tc.expectedErr) {
			t.Errorf("kd(%s) returned unexpected error: got %v, want %v", tc.path, err, tc.expectedErr)
		}

		// Compare Xtd fields or use custom comparison logic if needed
		// Example comparison:
		// if !reflect.DeepEqual(xtd, tc.expectedXtd) {
		// 	t.Errorf("kd(%s) returned unexpected Xtd: got %+v, want %+v", tc.path, xtd, tc.expectedXtd)
		// }
	}
}

func TestHTree(t *testing.T) {
	t.Run("Child", ChildTest)
	t.Run("CreateChild", CreateChildTest)
	t.Run("KeyAt", KeyAtTest)
	t.Run("Addr", AddrTest)
	t.Run("Kd", KdTest)
}
