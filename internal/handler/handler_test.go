package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nil-nil/test-signer/internal/repository"
	"github.com/nil-nil/test-signer/internal/service"
	"github.com/nil-nil/test-signer/internal/signer"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/nacl/sign"
)

func TestVerify(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://postgres:@127.0.0.1:5434/toggl")
	if err != nil {
		panic(err)
	}
	repo := repository.NewRepository(pool)
	_, priv, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := signer.NewNaclSigner(priv)
	svc := service.NewSignatureService(repo, signer)
	h := NewHandler(svc)

	t.Run("TestSuccess", func(t *testing.T) {
		sig, err := svc.SignAnswers(context.Background(), 10, map[string]string{"foo": "qux"})
		if err != nil {
			panic(err)
		}
		expectJson, err := json.Marshal(sig)
		if err != nil {
			panic(err)
		}

		r, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("/signatures/%s", base64.URLEncoding.EncodeToString([]byte(sig.Key))), nil)
		claims := &validator.ValidatedClaims{
			RegisteredClaims: validator.RegisteredClaims{
				Subject: "10",
			},
		}
		r = r.WithContext(context.WithValue(r.Context(), jwtmiddleware.ContextKey{}, claims))
		w := httptest.NewRecorder()

		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code, "expect no error")
		body, err := io.ReadAll(w.Body)
		if err != nil {
			panic(err)
		}
		assert.JSONEq(t, string(expectJson), string(body), "expect correct json")
	})
}

func TestSign(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://postgres:@127.0.0.1:5434/toggl")
	if err != nil {
		panic(err)
	}
	repo := repository.NewRepository(pool)
	_, priv, err := sign.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := signer.NewNaclSigner(priv)
	svc := service.NewSignatureService(repo, signer)
	h := NewHandler(svc)

	t.Run("TestSuccess", func(t *testing.T) {
		requestBody, err := json.Marshal(map[string]string{"baz": "qux", "foo": "bar"})
		if err != nil {
			panic(err)
		}
		r, _ := http.NewRequest(http.MethodPost, "/signatures", bytes.NewReader(requestBody))
		claims := &validator.ValidatedClaims{
			RegisteredClaims: validator.RegisteredClaims{
				Subject: "9",
			},
		}
		r = r.WithContext(context.WithValue(r.Context(), jwtmiddleware.ContextKey{}, claims))
		w := httptest.NewRecorder()

		h.ServeHTTP(w, r)
		assert.Equal(t, http.StatusCreated, w.Code, "expect no error")
		body, err := io.ReadAll(w.Body)
		if err != nil {
			panic(err)
		}
		var sig service.Signature
		err = json.Unmarshal(body, &sig)
		if err != nil {
			panic(err)
		}
		assert.Equal(t, uint(9), sig.UserID, "expect given values")
		assert.Equal(t, map[string]string{"baz": "qux", "foo": "bar"}, sig.Test, "expect given values")
	})
}
