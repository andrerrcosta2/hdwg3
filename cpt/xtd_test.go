package cpt

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hdwg3/_test"
	"hdwg3/pck"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaster(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, err := Master(seed, _test.KEY_SPEC)
	assert.NoError(t, err)
	assert.NotNil(t, xtd)
	assert.Equal(t, 32, len(xtd.Key))
	assert.Equal(t, 32, len(xtd.Cc))
	sha256.New()
}

func TestSer(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)
	ser, err := xtd.Ser()
	assert.NoError(t, err)
	assert.NotEmpty(t, ser)
}

func TestChild(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	ck, err := xtd.Child(0)
	assert.NoError(t, err)
	assert.NotNil(t, ck)
	assert.Equal(t, xtd.Dep+1, ck.Dep)
	assert.Equal(t, uint32(0), ck.Chn)
}

func TestFpt(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)
	fin := xtd.Fpt()

	pub, _ := xtd.Pub()
	h := sha256.New()
	h.Write(pub.SerializeCompressed())
	res := binary.BigEndian.Uint32(h.Sum(nil)[:4])

	assert.Equal(t, fin, res)
}

func TestCD(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)
	err := xtd.canDerive(0)
	assert.NoError(t, err)

	err = xtd.canDerive(0x80000000)
	assert.NoError(t, err)

	xtd.IsPvt = false
	err = xtd.canDerive(0x80000000)

	assert.Error(t, err)
}

func TestPd(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	dat, err := xtd.pd(0)
	assert.NoError(t, err)
	assert.NotEmpty(t, dat)
}

func TestCk(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	dat, _ := xtd.pd(0)
	hmac := pck.HmacSHA512(xtd.Cc, dat)
	ck, err := xtd.ck(hmac)
	assert.NoError(t, err)
	assert.NotEmpty(t, ck)
}

func TestCek(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	dat, _ := xtd.pd(0)
	hmac := pck.HmacSHA512(xtd.Cc, dat)
	ck, _ := xtd.ck(hmac)
	cek := xtd.cek(ck, hmac[32:], 0)
	assert.NotNil(t, cek)
	assert.Equal(t, xtd.Dep+1, cek.Dep)
	assert.Equal(t, xtd.Fpt(), cek.Fin)
	assert.Equal(t, uint32(0), cek.Chn)
}

func TestSkd(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	skd, err := xtd.skd()
	assert.NoError(t, err)
	assert.NotEmpty(t, skd)
}

func TestSvn(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	xtd, _ := Master(seed, _test.KEY_SPEC)

	_v := xtd.svn()
	assert.NotEmpty(t, _v)
}
