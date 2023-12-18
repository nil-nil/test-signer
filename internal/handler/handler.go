package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/nil-nil/test-signer/internal/service"
)

type Handler struct {
	svc *service.SignatureService
}

func NewHandler(svc *service.SignatureService) *Handler {
	return &Handler{svc}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the JWT claims
	claims, ok := r.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
	if !ok {
		http.Error(w, "failed to get validated claims", http.StatusUnauthorized)
		return
	}

	// Get the user ID subject
	var (
		sub uint64
		err error
	)
	if sub, err = strconv.ParseUint(claims.RegisteredClaims.Subject, 10, 32); err != nil || sub == 0 {
		http.Error(w, "failed to get subject claim", http.StatusUnauthorized)
		return
	}

	// Route the request
	var payload []byte
	switch {
	case r.Method == http.MethodGet:
		payload, err = h.VerifySignature(uint(sub), r)
		// Return 404 for non-matching signatures so as not to leak that the signature exists for a different user
		if errors.Is(err, service.ErrNotFound) || errors.Is(err, service.ErrNoMatch) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
	case r.Method == http.MethodPost:
		payload, err = h.SignAnswers(uint(sub), r)
		if err != nil {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
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
