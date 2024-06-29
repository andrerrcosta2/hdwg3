// Created by André R R Costa ** github.com/andrerrcosta2
// File: mnmc.go
// Date:
// Description:
// --------------------------------------------------------------

package md

import "strings"

type Mnmc struct {
	values []string
}

func NewMnmc(values ...string) *Mnmc {
	return &Mnmc{values: values}
}

func (m *Mnmc) String() string {
	return strings.Join(m.values, " ")
}

func (m *Mnmc) Byte() []byte {
	return []byte(m.String())
}
