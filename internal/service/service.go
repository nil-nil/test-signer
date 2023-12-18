package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNotFound             = errors.New("not found in repository")
	ErrNoMatch              = errors.New("signature key and user do not match")
	ErrOtherRepositoryError = errors.New("unkexpected repository error")
	ErrInternalError        = errors.New("unexpected service error")
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

type Signer interface {
	Sign(ctx context.Context, payload []byte) (string, error)
}

type SignatureService struct {
	repo   Repository
	signer Signer
}

func NewSignatureService(repo Repository, signer Signer) *SignatureService {
	return &SignatureService{repo, signer}
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

func (s *SignatureService) SignAnswers(ctx context.Context, userID uint, test map[string]string) (Signature, error) {
	// Generate a JSON payload
	payload, err := json.Marshal(struct {
		UserID uint              `json:"userId"`
		Test   map[string]string `json:"test"`
	}{userID, test})
	if err != nil {
		return Signature{}, errors.Join(ErrInternalError, err)
	}

	// Sign the payload
	key, err := s.signer.Sign(ctx, payload)
	if err != nil {
		return Signature{}, errors.Join(err, ErrInternalError)
	}

	// Save the signature
	sig := Signature{
		Key:       base64.URLEncoding.EncodeToString([]byte(key)),
		Test:      test,
		UserID:    userID,
		Timestamp: time.Now(),
	}
	err = s.repo.SaveSignature(ctx, sig)
	if err != nil {
		return Signature{}, errors.Join(ErrOtherRepositoryError, err)
	}

	return sig, nil
}
