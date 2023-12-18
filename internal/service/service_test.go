package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignatureVerification(t *testing.T) {
	repo := &mockRepo{}
	svc := NewSignatureService(repo)

	t.Run("TestNotFound", func(t *testing.T) {
		repo.getSignatureFunc = func(ctx context.Context, key string) (Signature, error) {
			return Signature{}, ErrNotFound
		}

		sig, err := svc.VerifySignature(context.Background(), 0, "")
		assert.ErrorIs(t, err, ErrNotFound, "expect relevant error")
		assert.Zero(t, sig, "expect zero signature on error")
	})

	t.Run("TestOtherError", func(t *testing.T) {
		repo.getSignatureFunc = func(ctx context.Context, key string) (Signature, error) {
			return Signature{}, errors.New("unexpected error")
		}

		sig, err := svc.VerifySignature(context.Background(), 0, "")
		assert.ErrorIs(t, err, ErrOtherRepositoryError, "expect relevant error")
		assert.Zero(t, sig, "expect zero signature on error")
	})

	t.Run("TestInvalidUser", func(t *testing.T) {
		repo.getSignatureFunc = func(ctx context.Context, key string) (Signature, error) {
			return Signature{
				UserID: 1,
			}, nil
		}

		sig, err := svc.VerifySignature(context.Background(), 0, "")
		assert.ErrorIs(t, err, ErrNoMatch, "expect relevant error")
		assert.Zero(t, sig, "expect zero signature on error")
	})

	t.Run("TestValid", func(t *testing.T) {
		expect := Signature{
			Key:       "someData",
			UserID:    1,
			Test:      map[string]string{"foo": "bar"},
			Timestamp: time.Now().Add(-5 * time.Hour),
		}
		repo.getSignatureFunc = func(ctx context.Context, key string) (Signature, error) {
			return expect, nil
		}

		sig, err := svc.VerifySignature(context.Background(), 1, "someData")
		assert.NoError(t, err, ErrNoMatch, "expect no error")
		assert.Equal(t, expect, sig, "expect valid signature")
	})
}

type mockRepo struct {
	saveSignatureFunc func(ctx context.Context, signature Signature) error
	getSignatureFunc  func(ctx context.Context, key string) (Signature, error)
}

func (m *mockRepo) SaveSignature(ctx context.Context, signature Signature) error {
	return m.saveSignatureFunc(ctx, signature)
}

func (m *mockRepo) GetSignature(ctx context.Context, key string) (Signature, error) {
	return m.getSignatureFunc(ctx, key)
}
