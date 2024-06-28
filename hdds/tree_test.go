package hdds

import (
	"hdwg3/_test"
	"hdwg3/md"
	"sync"
	"testing"
)

// ChildTest tests the Child method of HTree.
func ChildTest(t *testing.T) {
	// Mock setup
	mockKey := &md.Xtd{
		Key:   []byte{},
		Cc:    []byte{},
		Dep:   0,
		Fin:   0,
		Chn:   0,
		IsPvt: true,
	}
	mockIOS := MockIOS{} // Mock implementation of io.IOS
	mockHTree := &HTree{
		Key:  mockKey,
		IOS:  mockIOS,
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}

	// Test cases
	testCases := []struct {
		index       uint32
		expectedErr error
	}{
		{index: 0, expectedErr: nil}, // Replace with expected error or nil
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		child, err := mockHTree.Child(tc.index)
		if err != tc.expectedErr {
			t.Errorf("Child(%d) returned unexpected error: got %v, want %v", tc.index, err, tc.expectedErr)
		}

		// Optionally, add assertions to verify child struct properties or behavior
	}
}

// CreateChildTest tests the CreateChild method of HTree.
func CreateChildTest(t *testing.T) {
	// Mock setup
	mockKey := &md.Xtd{
		Key:   []byte{ /* Mock key bytes */ },
		Cc:    []byte{ /* Mock chain code bytes */ },
		Dep:   0,    // Mock depth
		Fin:   0,    // Mock fingerprint
		Chn:   0,    // Mock child index
		IsPvt: true, // Mock private key status
	}
	mockIOS := MockIOS{} // Mock implementation of io.IOS
	mockHTree := &MockHTree{
		Key:  mockKey,
		IOS:  mockIOS,
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}

	// Test cases
	testCases := []struct {
		index       uint32
		expectedErr error
	}{
		{index: 0, expectedErr: nil}, // Replace with expected error or nil
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		child, err := mockHTree.CreateChild(tc.index)
		if err != tc.expectedErr {
			t.Errorf("CreateChild(%d) returned unexpected error: got %v, want %v", tc.index, err, tc.expectedErr)
		}

		// Optionally, add assertions to verify child struct properties or behavior
	}
}

// KeyAtTest tests the KeyAt method of HTree.
func KeyAtTest(t *testing.T) {
	// Mock setup
	mockKey := &md.Xtd{
		Key:   []byte{ /* Mock key bytes */ },
		Cc:    []byte{ /* Mock chain code bytes */ },
		Dep:   0,    // Mock depth
		Fin:   0,    // Mock fingerprint
		Chn:   0,    // Mock child index
		IsPvt: true, // Mock private key status
	}
	mockIOS := MockIOS{} // Mock implementation of io.IOS
	mockHTree := &MockHTree{
		Key:  mockKey,
		IOS:  mockIOS,
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
		mtx:  sync.Mutex{},
	}

	// Test cases
	testCases := []struct {
		path        []uint32
		expectedErr error
	}{
		{path: []uint32{0, 1, 2}, expectedErr: nil}, // Replace with expected error or nil
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		child, err := mockHTree.KeyAt(tc.path)
		if err != tc.expectedErr {
			t.Errorf("KeyAt(%v) returned unexpected error: got %v, want %v", tc.path, err, tc.expectedErr)
		}

		// Optionally, add assertions to verify child struct properties or behavior
	}
}

func TestHTree(t *testing.T) {
	t.Run("Child", ChildTest)
	t.Run("CreateChild", CreateChildTest)
	t.Run("KeyAt", KeyAtTest)
}

func AddrTest(t *testing.T) {

	mockKey := &md.Xtd{
		Key:   []byte{},
		Cc:    []byte{},
		Dep:   0,
		Fin:   0,
		Chn:   0,
		IsPvt: true,
	}
	mockHTree := &HTree{
		Key:  mockKey,
		IOS:  _test.MockIOS{},
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
	}

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
	// Mock setup
	mockKey := &md.Xtd{
		Key:   []byte{ /* Mock key bytes */ },
		Cc:    []byte{ /* Mock chain code bytes */ },
		Dep:   0,    // Mock depth
		Fin:   0,    // Mock fingerprint
		Chn:   0,    // Mock child index
		IsPvt: true, // Mock private key status
	}
	mockHTree := &HTree{
		Key:  mockKey,
		IOS:  MockHTreeIOS{}, // Mock implementation of io.IOS
		Fn:   "mock_filename",
		Pass: "mock_password",
		Chn:  make(map[uint32]*HTree),
	}

	// Test cases
	testCases := []struct {
		path        string
		expectedXtd *md.Xtd
		expectedErr error
	}{
		{path: "m/44'/0'/0'/0/0", expectedXtd: &md.Xtd{}, expectedErr: nil}, // Replace with expected Xtd and error
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		xtd, err := mockHTree.kd(tc.path)
		if err != tc.expectedErr {
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
	t.Run("Addr", AddrTest)
	t.Run("Kd", KdTest)
}
