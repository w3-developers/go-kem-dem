package kemdem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKemDem(t *testing.T) {
	kp, err := GenerateKeyPair()
	assert.NoError(t, err)

	pub := PubKeyToHexString(kp.Pub)
	priv := PrivKeyToHexString(kp.Priv)

	msg := "79999999999_1ee25102525dcaec245493dc552106f9fd29316be0073d603228e952ead69759"

	enc, err := Encrypt(pub, msg)
	assert.NoError(t, err)

	dec, err := Decrypt(priv, enc)
	assert.NoError(t, err)

	assert.Equal(t, msg, dec, "decrypted message should be equal original")
}
