package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrGettingToken   = errors.New("unable to get token from token string")
	ErrTokenInvalid   = errors.New("token failed validity check")
	ErrGettingClaims  = errors.New("unable to get claims from token")
	ErrGettingSubject = errors.New("token claims does not have a subject")
	ErrInvalidSubject = errors.New("token subject is not valid")
	ErrGettingUser    = errors.New("error getting user for subject")
	ErrInvalidAlg     = errors.New("invalid token alg")
)

type jwtAuthProvider struct {
	publicKey     interface{}
	privateKey    interface{}
	tokenLifetime uint64
}

func NewJwtAuthProvider(
	publicKeyBytes []byte,
	privateKeyBytes []byte,
	tokenLifetime uint64,
) (jwtAuthProvider, error) {
	var (
		publicKey  interface{}
		privateKey interface{}
		err        error
	)

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return jwtAuthProvider{}, fmt.Errorf("unable to parse public key: %w", err)
	}
	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return jwtAuthProvider{}, fmt.Errorf("unable to parse private key: %w", err)
	}

	return jwtAuthProvider{
		publicKey:     publicKey,
		privateKey:    privateKey,
		tokenLifetime: tokenLifetime,
	}, nil
}

func (p jwtAuthProvider) GetUser(ctx context.Context, tokenString string) (uint, error) {
	token, err := p.getToken(tokenString)
	if err != nil {
		return 0, errors.Join(ErrGettingToken, err)
	}
	if token != nil && !token.Valid {
		return 0, ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrGettingClaims
	}

	// We're using the "sub" claim for the user ID
	sub, ok := claims["sub"]
	if !ok {
		return 0, ErrGettingSubject
	}

	return uint(sub.(float64)), nil
}

func (p jwtAuthProvider) NewToken(userID uint) (string, error) {
	if userID == 0 {
		return "", fmt.Errorf("invalid jwt subject for user %+v", userID)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"sub": userID,
		"nbf": time.Now().Unix(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Second * time.Duration(p.tokenLifetime)).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	return token.SignedString(p.privateKey)
}

func (p jwtAuthProvider) ValidateToken(tokenString string) (err error) {
	token, err := p.getToken(tokenString)
	if err != nil {
		return errors.Join(ErrGettingToken, err)
	}
	if !token.Valid {
		return ErrTokenInvalid
	}
	return nil
}

func (p jwtAuthProvider) getToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Check the signing method
		if t.Method.Alg() != "RS512" {
			return nil, ErrInvalidAlg
		}

		return p.publicKey, nil
	})
}
