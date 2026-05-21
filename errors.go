package kemdem

import "errors"

var (
	errKemDemCiphertextTooShort        = errors.New("ciphertext too short")
	errKemDemCiphertextTooShortNoNonce = errors.New("ciphertext too short (no nonce)")
)
