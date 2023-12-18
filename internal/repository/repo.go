package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nil-nil/test-signer/internal/service"
)

type Repository struct {
	pool *pgxpool.Pool
}

func (r *Repository) SaveSignature(ctx context.Context, signature service.Signature) error {
	_, err := r.pool.Exec(
		ctx,
		"INSERT INTO signatures (key, test, user_id, timestamp) VALUES ($1, $2, $3, $4)",
		signature.Key, signature.Test, signature.UserID, signature.Timestamp,
	)
	return err
}

func (r *Repository) GetSignature(ctx context.Context, key string) (service.Signature, error) {
	var sig service.Signature
	row := r.pool.QueryRow(ctx, "SELECT key, test, user_id, timestamp::timestamptz FROM signatures WHERE key = $1", key)
	if err := row.Scan(&sig.Key, &sig.Test, &sig.UserID, &sig.Timestamp); err != nil {
		return service.Signature{}, err
	}

	return sig, nil
}
