package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nil-nil/test-signer/internal/handler"
	"github.com/nil-nil/test-signer/internal/repository"
	"github.com/nil-nil/test-signer/internal/service"
	"github.com/nil-nil/test-signer/internal/signer"
	"golang.org/x/crypto/nacl/sign"
)

const (
	jwtPrivateKeyFilePath = "jwtRS512.key"
	jwtPublicKeyFilePath  = "jwtRS512.pub"
	naclFilePath          = "nacl.key"
)

func main() {
	dsn := flag.String("db", "postgres://postgres:@127.0.0.1:5434/toggl", "Database connection string")
	host := flag.String("host", "localhost:3000", "Server host")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		panic("need a command")
	}

	switch args[0] {
	case "run":
		jwtPrivateBytes, err := os.ReadFile(jwtPrivateKeyFilePath)
		if err != nil {
			fmt.Println("unable to read jwt private key file")
			panic(err)
		}
		jwtPublicBytes, err := os.ReadFile(jwtPublicKeyFilePath)
		if err != nil {
			fmt.Println("unable to read jwt public key file")
			panic(err)
		}

		naclKey, err := os.ReadFile(naclFilePath)
		if err != nil {
			panic(err)
		}
		naclKeyBytes := ([64]byte)(naclKey)

		// Set up the handler
		slog.Info("connecting to", "db", *dsn)
		pool, err := pgxpool.New(context.Background(), *dsn)
		if err != nil {
			panic(err)
		}
		repo := repository.NewRepository(pool)
		signer := signer.NewNaclSigner(&naclKeyBytes)
		svc := service.NewSignatureService(repo, signer)
		auth, err := handler.NewJwtAuthProvider(jwtPublicBytes, jwtPrivateBytes, 14400)
		if err != nil {
			panic(err)
		}
		h := handler.NewHandler(svc, auth)

		slog.Info("listening on", "host", *host)

		http.ListenAndServe(*host, h)
	case "init":
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaPrivatePem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivateKey),
			},
		)
		os.WriteFile(jwtPrivateKeyFilePath, rsaPrivatePem, 0700)
		rsaPublicPem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&rsaPrivateKey.PublicKey),
			},
		)
		os.WriteFile(jwtPublicKeyFilePath, rsaPublicPem, 0700)

		_, naclKey, err := sign.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		b, err := x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(naclKey[:]))
		if err != nil {
			panic(err)
		}
		naclPem := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: b,
			},
		)
		os.WriteFile(naclFilePath, naclPem, 0700)
	case "token":
		args = args[1:]
		jwtBytes, err := os.ReadFile(jwtPrivateKeyFilePath)
		if err != nil {
			fmt.Println("unable to read jwt key file")
			panic(err)
		}
		jwtKey, err := jwt.ParseRSAPrivateKeyFromPEM(jwtBytes)
		if err != nil {
			fmt.Println("unable to parse jwt key")
			panic(err)
		}

		userID, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			fmt.Println("invalid user ID")
			panic(err)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"sub": userID,
			"iss": "https://localhost",
			"aud": "localhost",
		})
		s, err := token.SignedString(jwtKey)
		if err != nil {
			fmt.Println("unable to sign jwt")
			panic(err)
		}
		fmt.Println(s)

	default:
		panic("unknown command")
	}
}
