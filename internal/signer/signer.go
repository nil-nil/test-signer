package signer

import (
	"context"

	"golang.org/x/crypto/nacl/sign"
)

type Signer struct {
	privateKey *[64]byte
}

func (s *Signer) Sign(_ context.Context, payload []byte) (string, error) {
	out := sign.Sign(nil, payload, s.privateKey)

	return string(out), nil
}
