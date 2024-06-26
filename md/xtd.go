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
	"hdwg3/pkc"
	"math/big"
)

/**
Example Usage in the HD Wallet Tree
Master Node:

Has Depth of 0, no ParentFingerprint, and a ChildNumber of 0.
Example: m (master node)
Child Node:

Derived from the master node with a specific ChildNumber and incremented Depth.
Example: m/0' (first hardened child of the master node)
Example: m/0'/1 (first normal child of the first hardened child)
Chain Code and Key:

Together, they enable the derivation of subsequent keys, maintaining the hierarchical and
deterministic properties of the wallet structure.
*/

// Xtd represents an extended key in the HD wallet.
type Xtd struct {
	// The private key is used to derive child private keys, and the public key is used to derive child
	// public keys. For the master node, this is the master private key derived from the seed.
	Key []byte // The cryptographic key (either a private key or public key) in byte form.
	// Each node in the HD wallet tree has a chain code, which helps in generating the next level of child
	// keys securely.
	ChainCode []byte // The chain code used for deriving child keys, providing additional entropy.
	// Helps to identify the hierarchical level of the key within the tree structure. This is important for
	// traversing the tree and understanding the key's position.
	Depth byte // The depth level in the HD wallet tree (0 for master node, 1 for immediate children, etc.).
	// Ensures integrity by identifying the parent key. Useful in verifying that a key was derived from
	// the expected parent.
	ParentFingerprint uint32 // A fingerprint of the parent key, used to prevent circular derivation.
	// Specifies the exact position of the key among its siblings, allowing for precise navigation and
	// derivation paths (e.g., m/0/1/2).
	ChildNumber uint32 // The index of the key in the derivation path (e.g., 0, 1, 2, ..., 2^31-1 for normal keys; 2^31 to 2^32-1 for hardened keys).
	// Determines the type of key and the operations that can be performed with it. Only private keys
	// can be used to derive both private and public child keys, while public keys can only derive public
	// child keys.
	IsPrivate bool // Indicates if the key is a private key (true) or a public key (false).
}

// NewMaster creates a new master extended key from the seed.
func NewMaster(seed []byte) (*Xtd, error) {
	key, chainCode := pkc.DMaK(seed, "Bitcoin seed")
	return &Xtd{
		Key:       key,
		ChainCode: chainCode,
		IsPrivate: true,
	}, nil
}

// Serialize serializes the extended key to a Base58-encoded string.
func (e *Xtd) Serialize() string {
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
	return e.Serialize()
}

// Child derives a child key from the extended key.
func (e *Xtd) Child(index uint32) (*Xtd, error) {
	if index >= hdkeychain.HardenedKeyStart && !e.IsPrivate {
		return nil, errors.New("cannot derive hardened key from public key")
	}

	var data []byte
	if index >= hdkeychain.HardenedKeyStart {
		// Hardened child
		data = append([]byte{0x00}, e.Key...)
	} else {
		// Normal child
		pubKey, err := e.PublicKey()
		if err != nil {
			return nil, err
		}
		data = pubKey.SerializeCompressed()
	}
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, index)
	data = append(data, indexBytes...)

	hmac := hmac.New(sha512.New, e.ChainCode)
	hmac.Write(data)
	I := hmac.Sum(nil)

	il := new(big.Int).SetBytes(I[:32])
	il = il.Mod(il, btcec.S256().N)
	if il.Sign() == 0 {
		return nil, errors.New("invalid child key")
	}

	childKey := new(big.Int).Add(new(big.Int).SetBytes(e.Key), il)
	childKey = childKey.Mod(childKey, btcec.S256().N)
	childKeyBytes := childKey.Bytes()

	childChainCode := I[32:]
	return &Xtd{
		Key:               childKeyBytes,
		ChainCode:         childChainCode,
		Depth:             e.Depth + 1,
		ParentFingerprint: e.Fingerprint(),
		ChildNumber:       index,
		IsPrivate:         e.IsPrivate,
	}, nil
}

// PublicKey returns the public key corresponding to the private key.
func (e *Xtd) PublicKey() (*btcec.PublicKey, error) {
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), e.Key)
	return privKey.PubKey(), nil
}

// Fingerprint returns the fingerprint of the extended key.
func (e *Xtd) Fingerprint() uint32 {
	pubKey, _ := e.PublicKey()
	h := sha256.New()
	h.Write(pubKey.SerializeCompressed())
	fingerprint := h.Sum(nil)[:4]
	return binary.BigEndian.Uint32(fingerprint)
}
