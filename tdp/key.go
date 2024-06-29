/*
	André R R Costa ** github.com/andrerrcosta2
*/

package tdp

import (
	"crypto/rand"
	"fmt"
)

func Rand(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	return b, nil
}
