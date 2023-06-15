package credentials

import (
	"context"

	"github.com/alexedwards/argon2id"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
)

const CredentialsUsername = "usertest"
const CredentialsPassword = "passtest"

type CredentialsStore interface {
	GetCredentialsByUsername(ctx context.Context, username string) (*model.Credentials, error)
}

type credentialsStore struct {
	memoryStore map[string]model.Credentials
	logger      *zap.Logger
}

func NewCredentialsStore(logger *zap.Logger) CredentialsStore {
	hash, err := argon2id.CreateHash(CredentialsPassword, argon2id.DefaultParams)
	if err != nil {
		panic("could not hash password to store credentials")
	}
	credentials := map[string]model.Credentials{
		CredentialsUsername: {
			Username: CredentialsUsername,
			Password: hash,
		},
	}
	return &credentialsStore{
		memoryStore: credentials,
		logger:      logger,
	}
}

func (c *credentialsStore) GetCredentialsByUsername(ctx context.Context, username string) (*model.Credentials, error) {
	if item, found := c.memoryStore[username]; found {
		return &item, nil
	}
	return nil, nil
}
