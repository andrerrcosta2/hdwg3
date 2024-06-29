// Created by André R R Costa
// File: xtd.go
// Date:
// Description:
// --------------------------------------------------------------

package cpt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/btcsuite/btcutil/hdkeychain"
	"hdwg3/pck"
	"math/big"
)

type Xtd struct {
	Key   []byte
	Cc    []byte
	Dep   byte
	Fin   uint32
	Chn   uint32
	IsPvt bool
}

func Master(seed []byte, keySpec string) (*Xtd, error) {
	key, cc := pck.MK(seed, keySpec)
	return &Xtd{
		Key:   key,
		Cc:    cc,
		IsPvt: true,
	}, nil
}

func (x *Xtd) Ser() (string, error) {
	_v := x.svn()

	cc := x.Cc
	if len(cc) != 32 {
		return "", errors.New("invalid chain code")
	}

	kd, err := x.skd()
	if err != nil {
		return "", err
	}

	dep := []byte{x.Dep}

	fin := make([]byte, 4)
	binary.BigEndian.PutUint32(fin, x.Fin)

	chn := make([]byte, 4)
	binary.BigEndian.PutUint32(chn, x.Chn)

	ser := bytes.Join([][]byte{_v, dep, fin, chn, cc, kd}, []byte{})

	chksum := sha256.Sum256(ser)
	chksum = sha256.Sum256(chksum[:])
	ser = append(ser, chksum[:4]...)

	return base58.Encode(ser), nil
}

func (x *Xtd) String() (string, error) {
	return x.Ser()
}

func (x *Xtd) Child(i uint32) (*Xtd, error) {
	if err := x.canDerive(i); err != nil {
		return nil, err
	}

	dat, err := x.pd(i)
	if err != nil {
		return nil, err
	}

	I := pck.HmacSHA512(x.Cc, dat)

	ck, err := x.ck(I)
	if err != nil {
		return nil, err
	}

	return &Xtd{
		Key:   ck,
		Cc:    I[32:],
		Dep:   x.Dep + 1,
		Fin:   x.Fpt(),
		Chn:   i,
		IsPvt: x.IsPvt,
	}, nil
}

func (x *Xtd) Pub() (*btcec.PublicKey, error) {
	prk, _ := btcec.PrivKeyFromBytes(btcec.S256(), x.Key)
	return prk.PubKey(), nil
}

func (x *Xtd) Fpt() uint32 {
	pub, _ := x.Pub()
	sh := pck.HSP(sha256.New, pub.SerializeCompressed())
	return binary.BigEndian.Uint32(sh[:4])
}

func (x *Xtd) canDerive(i uint32) error {
	if isHdn(i) && !x.IsPvt {
		return errors.New("cannot derive hardened from public key")
	}
	return nil
}

func (x *Xtd) pd(i uint32) ([]byte, error) {
	var dat []byte
	if isHdn(i) {
		dat = append([]byte{0x00}, x.Key...)
	} else {
		pub, err := x.Pub()
		if err != nil {
			return nil, err
		}
		dat = pub.SerializeCompressed()
	}

	bit := make([]byte, 4)
	binary.BigEndian.PutUint32(bit, i)
	dat = append(dat, bit...)

	return dat, nil
}

func (x *Xtd) ck(I []byte) ([]byte, error) {
	il := new(big.Int).SetBytes(I[:32])
	il = il.Mod(il, btcec.S256().N)
	if il.Sign() == 0 {
		return nil, errors.New("invalid child tdp")
	}

	childKey := new(big.Int).Add(new(big.Int).SetBytes(x.Key), il)
	childKey = childKey.Mod(childKey, btcec.S256().N)
	return childKey.Bytes(), nil
}

func (x *Xtd) cek(key, cc []byte, i uint32) *Xtd {
	return &Xtd{
		Key:   key,
		Cc:    cc,
		Dep:   x.Dep + 1,
		Fin:   x.Fpt(),
		Chn:   i,
		IsPvt: x.IsPvt,
	}
}

func (x *Xtd) svn() []byte {
	var v []byte
	if x.IsPvt {
		v = []byte{0x04, 0x88, 0xAD, 0xE4}
	} else {
		v = []byte{0x04, 0x88, 0xB2, 0x1E}
	}
	return v
}

func (x *Xtd) skd() ([]byte, error) {
	if x.IsPvt {
		return append([]byte{0x00}, x.Key...), nil
	} else {
		puk, err := x.Pub()
		if err != nil {
			return []byte{}, err
		}
		return puk.SerializeCompressed(), nil
	}
}

func isHdn(i uint32) bool {
	return i >= hdkeychain.HardenedKeyStart
}
