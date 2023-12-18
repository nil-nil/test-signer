package signer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/sign"
)

func TestSigning(t *testing.T) {
	pub, priv, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := &Signer{privateKey: priv}

	payload, err := json.Marshal(struct {
		UserID uint              `json:"userId"`
		Test   map[string]string `json:"test"`
	}{101, map[string]string{"baz": "qux"}})
	if err != nil {
		panic(err)
	}

	key, err := signer.Sign(context.Background(), payload)
	assert.NoError(t, err, "expect no error")
	assert.NotZero(t, key, "expect a key")

	got, ok := sign.Open(nil, []byte(key), pub)
	assert.True(t, ok, "expect key to validate")
	assert.Equal(t, payload, got, "expect payloads to match")
}
