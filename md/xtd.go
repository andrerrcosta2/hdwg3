package md

import (
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
	Key       []byte
	Cc        []byte
	Depth     byte
	Fpt       uint32
	Chn       uint32
	IsPrivate bool
}

func Master(seed []byte, keySpec string) (*Xtd, error) {
	key, cc := pck.DMaK(seed, keySpec)
	return &Xtd{
		Key:       key,
		Cc:        cc,
		IsPrivate: true,
	}, nil
}

func (e *Xtd) Ser() string {
	// This is a simplified serialization function for illustration.
	// Full serialization includes version bytes, checksum, etc.
	// See BIP-32 for full serialization details.
	var keyType byte
	if e.IsPrivate {
		keyType = 0x00
	} else {
		keyType = 0x02
	}
	return base58.Encode(append([]byte{keyType}, e.Key...))
}

func (e *Xtd) String() string {
	return e.Ser()
}

func (e *Xtd) Child(index uint32) (*Xtd, error) {
	if err := e.canDerive(index); err != nil {
		return nil, err
	}

	data, err := e.pd(index)
	if err != nil {
		return nil, err
	}

	I := e.genHMAC(data)

	ck, err := e.ck(I)
	if err != nil {
		return nil, err
	}

	childChainCode := I[32:]

	return e.cek(ck, childChainCode, index), nil
}

func (e *Xtd) Pub() (*btcec.PublicKey, error) {
	prk, _ := btcec.PrivKeyFromBytes(btcec.S256(), e.Key)
	return prk.PubKey(), nil
}

func (e *Xtd) GenFpt() uint32 {
	pub, _ := e.Pub()
	h := sha256.New()
	h.Write(pub.SerializeCompressed())
	fingerprint := h.Sum(nil)[:4]
	return binary.BigEndian.Uint32(fingerprint)
}

func (e *Xtd) canDerive(index uint32) error {
	if index >= hdkeychain.HardenedKeyStart && !e.IsPrivate {
		return errors.New("cannot derive hardened key from public key")
	}
	return nil
}

func (e *Xtd) pd(index uint32) ([]byte, error) {
	var data []byte
	if index >= hdkeychain.HardenedKeyStart {
		data = append([]byte{0x00}, e.Key...)
	} else {
		pubKey, err := e.Pub()
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

func (e *Xtd) genHMAC(data []byte) []byte {
	hmac := hmac.New(sha512.New, e.Cc)
	hmac.Write(data)
	return hmac.Sum(nil)
}

func (e *Xtd) ck(I []byte) ([]byte, error) {
	il := new(big.Int).SetBytes(I[:32])
	il = il.Mod(il, btcec.S256().N)
	if il.Sign() == 0 {
		return nil, errors.New("invalid child key")
	}

	childKey := new(big.Int).Add(new(big.Int).SetBytes(e.Key), il)
	childKey = childKey.Mod(childKey, btcec.S256().N)
	return childKey.Bytes(), nil
}

func (e *Xtd) cek(key, cc []byte, i uint32) *Xtd {
	return &Xtd{
		Key:       key,
		Cc:        cc,
		Depth:     e.Depth + 1,
		Fpt:       e.GenFpt(),
		Chn:       i,
		IsPrivate: e.IsPrivate,
	}
}
