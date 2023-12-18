package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/nil-nil/test-signer/internal/service"
)

type Handler struct {
	svc  *service.SignatureService
	auth AuthProvider
}

type userContextKey struct{}

var UserContextKey = userContextKey{}

func NewHandler(svc *service.SignatureService, auth AuthProvider) *Handler {
	return &Handler{svc, auth}
}

type AuthProvider interface {
	// NewToken creates a new token tied to the specfied user
	NewToken(userID uint) (token string, err error)

	// ValidateToken verifies that a token is valid and trusted by us
	ValidateToken(token string) (err error)

	// GetUser verifies that a token is valid and trusted by us, identifies the user it is tied to, and returns that user.
	//
	// ok tells us if the token is valid. err gives us additional information if the toke is invalid.
	GetUser(ctx context.Context, token string) (userID uint, err error)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the JWT and validate it
	authHeader := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		slog.Error("unauthorized request", "err", "invalid token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	sub, err := h.auth.GetUser(r.Context(), token)
	if err != nil {
		slog.Error("unauthorized request", "err", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Route the request
	var payload []byte
	switch {
	case strings.HasPrefix(r.URL.Path, "/signatures"):
		switch {
		case r.Method == http.MethodGet:
			payload, err = h.VerifySignature(sub, r)
			// Return 404 for non-matching signatures so as not to leak that the signature exists for a different user
			if errors.Is(err, service.ErrNotFound) || errors.Is(err, service.ErrNoMatch) {
				slog.Error("handler error", "err", err)
				http.NotFound(w, r)
				return
			}
			if err != nil {
				slog.Error("handler error", "err", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
		case r.Method == http.MethodPost:
			payload, err = h.SignAnswers(sub, r)
			if err != nil {
				slog.Error("handler error", "err", err)
				http.Error(w, "", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func (h *Handler) SignAnswers(userID uint, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	var test map[string]string
	err = json.Unmarshal(body, &test)
	if err != nil {
		return nil, err
	}

	sig, err := h.svc.SignAnswers(r.Context(), userID, test)
	if err != nil {
		return nil, err
	}

	return json.Marshal(sig)
}

var signatureExtract = regexp.MustCompile("^/signatures/(.*)$")

func (h *Handler) VerifySignature(userID uint, r *http.Request) ([]byte, error) {
	// Get the key from the url
	var key string
	if matches := signatureExtract.FindStringSubmatch(r.URL.Path); len(matches) == 2 {
		key = matches[1]
	} else {
		return nil, errors.New("unable to find signature in url path")
	}

	sig, err := h.svc.VerifySignature(r.Context(), userID, key)
	if err != nil {
		return nil, err
	}

	return json.Marshal(sig)
}
