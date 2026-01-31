package chatterbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

const FINGERPRINT_LENGTH = 32 // bytes

type PublicKey ecdsa.PublicKey

type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  PublicKey
}

type SymmetricKey struct {
	key []byte
}

// KEY GENERATION USING elliptic.P256 to generate 128bit key
// OFTEN IT IS BEST PRATICE TO LET USER GENERATE THEIR OWN KEY PAIRS.
// THIS IS ONLY FOR DEMONSTRATING PURPOSE!
func GenerateKeyPair() *KeyPair {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &KeyPair{
		PrivateKey: priv,
		PublicKey:  PublicKey(priv.PublicKey),
	}
}

// DH KEY EXCHANGE USING g^ab mod(p) = g^ba mod(p)
func DHCombine(pub *PublicKey, priv *ecdsa.PrivateKey) *SymmetricKey {
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	hash := sha256.Sum256(x.Bytes())
	return &SymmetricKey{key: hash[:]}
}

// CombineKeys combines multiple symmetric keys with SHA256 and produce Hash Mac.
// It contains Additional data attached, reffer to EncryptAdditional Data in chatter.go
func CombineKeys(keys ...*SymmetricKey) *SymmetricKey {
	h := hmac.New(sha256.New, []byte("combine"))
	for _, k := range keys {
		h.Write(k.key)
	}
	return &SymmetricKey{key: h.Sum(nil)}
}

// DeriveKey generates a new key from a given key
func (k *SymmetricKey) DeriveKey(label string) *SymmetricKey {
	h := hmac.New(sha256.New, k.key)
	h.Write([]byte(label))
	return &SymmetricKey{key: h.Sum(nil)}
}

// Copy a SymetricKey and return a pointer to that instance created.
func (k *SymmetricKey) Clone() *SymmetricKey {
	if k == nil {
		return nil
	}
	newKey := make([]byte, len(k.key))
	copy(newKey, k.key)
	return &SymmetricKey{key: newKey}
}

// Key returns a copy of the key bytes.
// ONLY FOR DEBUGGING PURPOSES.
func (k *SymmetricKey) Key() []byte {
	if k == nil || k.key == nil {
		return nil
	}
	keyCopy := make([]byte, len(k.key))
	copy(keyCopy, k.key)
	return keyCopy
}

// to avoid memory look up attack
func (kp *KeyPair) Zeroize() {
	if kp == nil || kp.PrivateKey == nil {
		return
	}
	if kp.PrivateKey.D != nil {
		kp.PrivateKey.D.SetInt64(0)
	}
	kp.PrivateKey.X, kp.PrivateKey.Y = nil, nil
}

// For symetric key.
func (k *SymmetricKey) Zeroize() {
	if k == nil || k.key == nil {
		return
	}
	// Overwrite with zeroes
	for i := range k.key {
		k.key[i] = 0
	}
	k.key = nil
}

// attach a tag onto the cyber text.
func (k *SymmetricKey) AuthenticatedEncrypt(plaintext string, aad []byte, iv []byte) []byte {
	block, _ := aes.NewCipher(k.key[:32]) // AES-256
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, iv, []byte(plaintext), aad)
}

// Symetric decryption
// and meta data parsing
func (k *SymmetricKey) AuthenticatedDecrypt(ciphertext []byte, aad []byte, iv []byte) (string, error) {
	block, _ := aes.NewCipher(k.key[:32])
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, iv, ciphertext, aad)
	return string(pt), err
}

// To check and identify if two entities correctly shared the keys.
func (p *PublicKey) Fingerprint() []byte {
	xBytes := p.X.Bytes()
	yBytes := p.Y.Bytes()
	buf := make([]byte, 64)
	copy(buf[32-len(xBytes):32], xBytes)
	copy(buf[64-len(yBytes):], yBytes)
	hash := sha256.Sum256(buf)
	return hash[:]
}

func NewIV() []byte {
	iv := make([]byte, 12) //Nonce N
	_, _ = io.ReadFull(rand.Reader, iv)
	return iv
}
