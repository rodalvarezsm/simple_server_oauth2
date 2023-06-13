package credentials

import (
	"context"

	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
)

type CredentialsStore interface {
	GetCredentialsByUsername(ctx context.Context, username string) (*model.Credentials, error)
}

type credentialsStore struct {
	memoryStore map[string]model.Credentials
	logger      *zap.Logger
}

func NewCredentialsStore(logger *zap.Logger) CredentialsStore {
	credentials := map[string]model.Credentials{
		"usertest": {
			Username: "usertest",
			Password: "passtest",
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
