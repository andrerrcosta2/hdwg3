package io

import (
	"github.com/andrerrcosta2/hdwg3/cpt"
	"github.com/andrerrcosta2/hdwg3/tdp"
	"github.com/stretchr/testify/mock"
)

const (
	ksz = 32
	csz = 32
)

// mockIoss ioss
type mockIoss struct {
	mock.Mock
}

func (m *mockIoss) StoreQuery(args ...interface{}) (string, error) {
	a := m.Called(args...)
	return a.String(0), a.Error(1)
}

func (m *mockIoss) LoadQuery(args ...interface{}) (string, error) {
	a := m.Called(args...)
	return a.String(0), a.Error(1)
}

func rck(dep byte, fin, chn uint32) *cpt.Xtd {
	key, _ := tdp.Rand(ksz)
	cc, _ := tdp.Rand(csz)
	return &cpt.Xtd{
		Key:   key,
		Cc:    cc,
		Dep:   dep,
		Fin:   fin,
		Chn:   chn,
		IsPvt: true,
	}
}
