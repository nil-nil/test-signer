package service

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound             = errors.New("not found in repository")
	ErrNoMatch              = errors.New("signature key and user do not match")
	ErrOtherRepositoryError = errors.New("unkexpected repository error")
)

type Signature struct {
	Key       string
	Test      map[string]string
	UserID    uint
	Timestamp time.Time
}

type Repository interface {
	SaveSignature(ctx context.Context, signature Signature) error
	GetSignature(ctx context.Context, key string) (Signature, error)
}

type SignatureService struct {
	repo Repository
}

func NewSignatureService(repo Repository) *SignatureService {
	return &SignatureService{repo}
}

func (s *SignatureService) VerifySignature(ctx context.Context, userID uint, key string) (Signature, error) {
	// Get the signature
	sig, err := s.repo.GetSignature(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return Signature{}, err
	}
	if err != nil {
		return Signature{}, errors.Join(ErrOtherRepositoryError, err)
	}

	// Verify the user owns the signature
	if sig.UserID != userID {
		return Signature{}, ErrNoMatch
	}

	return sig, nil
}
