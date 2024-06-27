package md

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
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
		return "", errors.New("chain code length invalid")
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

	checksum := sha256.Sum256(ser)
	checksum = sha256.Sum256(checksum[:])
	ser = append(ser, checksum[:4]...)

	return base58.Encode(ser), nil
}

func (x *Xtd) String() (string, error) {
	return x.Ser()
}

func (x *Xtd) Child(index uint32) (*Xtd, error) {
	if err := x.canDerive(index); err != nil {
		return nil, err
	}

	data, err := x.pd(index)
	if err != nil {
		return nil, err
	}

	I := x.hmac(data)

	ck, err := x.ck(I)
	if err != nil {
		return nil, err
	}

	childChainCode := I[32:]

	return x.cek(ck, childChainCode, index), nil
}

func (x *Xtd) Pub() (*btcec.PublicKey, error) {
	prk, _ := btcec.PrivKeyFromBytes(btcec.S256(), x.Key)
	return prk.PubKey(), nil
}

func (x *Xtd) Fingerprint() uint32 {
	pub, _ := x.Pub()
	h := sha256.New()
	h.Write(pub.SerializeCompressed())
	fingerprint := h.Sum(nil)[:4]
	return binary.BigEndian.Uint32(fingerprint)
}

func (x *Xtd) canDerive(index uint32) error {
	if index >= hdkeychain.HardenedKeyStart && !x.IsPvt {
		return errors.New("cannot derive hardened key from public key")
	}
	return nil
}

func (x *Xtd) pd(index uint32) ([]byte, error) {
	var data []byte
	if index >= hdkeychain.HardenedKeyStart {
		data = append([]byte{0x00}, x.Key...)
	} else {
		pubKey, err := x.Pub()
		if err != nil {
			return nil, err
		}
		data = pubKey.SerializeCompressed()
	}

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	data = append(data, indexBytes...)

	return data, nil
}

func (x *Xtd) hmac(data []byte) []byte {
	hmac := hmac.New(sha512.New, x.Cc)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func (x *Xtd) ck(I []byte) ([]byte, error) {
	il := new(big.Int).SetBytes(I[:32])
	il = il.Mod(il, btcec.S256().N)
	if il.Sign() == 0 {
		return nil, errors.New("invalid child key")
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
		Fin:   x.Fingerprint(),
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
