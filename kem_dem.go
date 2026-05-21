package kemdem

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Hybrid Public-Key Encryption: KEM + KDF + DEM (X25519 + HKDF + AEAD)
// 1. KEM (Key Encapsulation Mechanism):
// 		X25519 (Elliptic Curve Diffie–Hellman on Curve25519)
// 		an ephemeral key pair is generated from which, together with the recipient's public key, a shared secret is calculated.

// 2. KDF (Key Derivation Function):
// 		HKDF(SHA-256) extracts a fixed-size symmetric key from this secret.

// 3. DEM (Data Encapsulation Mechanism)
// 		The AEAD cipher (ChaCha20-Poly1305) encrypts the actual data.

type KeyPair struct {
	Priv *ecdh.PrivateKey
	Pub  *ecdh.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Priv: priv, Pub: priv.PublicKey()}, nil
}

func keyToHexString(key []byte) string {
	return hex.EncodeToString(key)
}

func PrivKeyToHexString(key *ecdh.PrivateKey) string {
	return keyToHexString(key.Bytes())
}

func PubKeyToHexString(key *ecdh.PublicKey) string {
	return keyToHexString(key.Bytes())
}

func deriveKey(shared, info []byte) []byte {
	h := hkdf.New(sha256.New, shared, nil, info)
	key := make([]byte, chacha20poly1305.KeySize)
	io.ReadFull(h, key)

	return key
}

func Encrypt(pub string, data string) (string, error) {
	curve := ecdh.X25519()
	pubBytes, err := hex.DecodeString(pub)
	if err != nil {
		return "", err
	}
	recipientPub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return "", err
	}

	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	ephPub := ephPriv.PublicKey()

	shared, err := ephPriv.ECDH(recipientPub)
	if err != nil {
		return "", err
	}

	key := deriveKey(shared, []byte("x25519+chacha20poly1305:v1"))
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ct := aead.Seal(nil, nonce, []byte(data), nil)
	out := append(ephPub.Bytes(), nonce...)
	out = append(out, ct...)

	return hex.EncodeToString(out), nil
}

func Decrypt(priv string, cipher string) (string, error) {
	curve := ecdh.X25519()
	const pubLen = 32

	privBytes, err := hex.DecodeString(priv)
	if err != nil {
		return "", err
	}
	recipientPriv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return "", err
	}

	blob, err := hex.DecodeString(cipher)
	if err != nil {
		return "", err
	}
	if len(blob) < pubLen {
		return "", errKemDemCiphertextTooShort
	}

	ephPubBytes := blob[:pubLen]
	ephPub, err := curve.NewPublicKey(ephPubBytes)
	if err != nil {
		return "", err
	}

	shared, err := recipientPriv.ECDH(ephPub)
	if err != nil {
		return "", err
	}

	key := deriveKey(shared, []byte("x25519+chacha20poly1305:v1"))
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}

	if len(blob) < pubLen+aead.NonceSize() {
		return "", errKemDemCiphertextTooShortNoNonce
	}
	nonce := blob[pubLen : pubLen+aead.NonceSize()]
	ct := blob[pubLen+aead.NonceSize():]

	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
