package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nil-nil/test-signer/internal/service"
	"github.com/stretchr/testify/assert"
)

var pool *pgxpool.Pool

func init() {
	var err error
	pool, err = pgxpool.New(context.Background(), "postgres://postgres:@127.0.0.1:5434/test")
	if err != nil {
		panic(err)
	}
	_, err = pool.Exec(context.Background(), "DELETE FROM signatures")
	if err != nil {
		panic(err)
	}
}

func TestSave(t *testing.T) {
	repo := Repository{pool}

	expect := service.Signature{
		Key:       "someKey",
		Test:      map[string]string{"foo": "bar", "baz": "qux"},
		UserID:    99,
		Timestamp: time.Now().Add(-5 * time.Hour),
	}

	err := repo.SaveSignature(context.Background(), expect)
	assert.NoError(t, err, "expect no error")
}

func TestVerify(t *testing.T) {
	repo := Repository{pool}
	expect := service.Signature{
		Key:       "otherKey",
		Test:      map[string]string{"foo": "bar", "baz": "qux"},
		UserID:    99,
		Timestamp: time.Now().Add(-5 * time.Hour),
	}
	_, err := pool.Exec(
		context.Background(),
		"INSERT INTO signatures (key, test, user_id, timestamp) VALUES ($1, $2, $3, $4)",
		expect.Key, expect.Test, expect.UserID, expect.Timestamp,
	)
	if err != nil {
		panic(err)
	}

	sig, err := repo.GetSignature(context.Background(), expect.Key)
	assert.NoError(t, err, "expect no error")
	assert.Equal(t, expect.Key, sig.Key, "expect values to match")
	assert.Equal(t, expect.UserID, sig.UserID, "expect values to match")
	assert.Equal(t, expect.Test, sig.Test, "expect values to match")
	assert.True(t, expect.Timestamp.Equal(sig.Timestamp), "expect timestamps to match")
}
