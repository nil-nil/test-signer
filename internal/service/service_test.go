package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignatureVerification(t *testing.T) {
	repo := &mockRepo{}
	svc := NewSignatureService(repo, nil)

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

func TestSignAnswers(t *testing.T) {
	repo := &mockRepo{}
	signer := &mockSigner{}
	svc := NewSignatureService(repo, signer)

	t.Run("TestSignerError", func(t *testing.T) {
		signer.signFunc = func(ctx context.Context, payload []byte) (string, error) {
			return "", errors.New("unexpected error")
		}

		sig, err := svc.SignAnswers(context.Background(), 1, map[string]string{"bar": "baz"})
		assert.ErrorIs(t, err, ErrInternalError, "expect relevant error")
		assert.Zero(t, sig, "expect zero signature on error")
	})

	t.Run("TestRepoError", func(t *testing.T) {
		signer.signFunc = func(ctx context.Context, payload []byte) (string, error) {
			return "somesignature", nil
		}
		repo.saveSignatureFunc = func(ctx context.Context, signature Signature) error {
			return errors.New("unexpected")
		}

		sig, err := svc.SignAnswers(context.Background(), 1, map[string]string{"bar": "baz"})
		assert.ErrorIs(t, err, ErrOtherRepositoryError, "expect relevant error")
		assert.Zero(t, sig, "expect zero signature on error")
	})

	t.Run("TestSuccess", func(t *testing.T) {
		var (
			expectKey  = "somesignature"
			expectUser = uint(5)
			expectTest = map[string]string{"bar": "baz"}
		)
		signer.signFunc = func(ctx context.Context, payload []byte) (string, error) {
			return expectKey, nil
		}
		repo.saveSignatureFunc = func(ctx context.Context, signature Signature) error {
			return nil
		}

		sig, err := svc.SignAnswers(context.Background(), expectUser, expectTest)
		assert.NoError(t, err, "expect no error")
		assert.Equal(t, expectUser, sig.UserID, "expect provided values")
		assert.Equal(t, expectTest, sig.Test, "expect provided values")
		assert.True(t, time.Since(sig.Timestamp) < 500*time.Millisecond, "exxpect recent timestamp")
		assert.Equal(t, base64.URLEncoding.EncodeToString([]byte(expectKey)), sig.Key, "Expect key returned by signer")
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

type mockSigner struct {
	signFunc func(ctx context.Context, payload []byte) (string, error)
}

func (m *mockSigner) Sign(ctx context.Context, payload []byte) (string, error) {
	return m.signFunc(ctx, payload)
}
