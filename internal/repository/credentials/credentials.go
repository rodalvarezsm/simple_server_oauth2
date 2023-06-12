package repository

import (
	"context"

	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
)

type CredentialsStore interface {
	GetCredentials(ctx context.Context, username string) (*model.Credentials, error)
}

type credentialsStore struct {
	memoryStore map[string]model.Credentials
	logger      *zap.Logger
}

func NewCredentialsStore(logger *zap.Logger) CredentialsStore {
	return &credentialsStore{
		logger: logger,
	}
}

func (c *credentialsStore) GetCredentials(ctx context.Context, username string) (*model.Credentials, error) {
	// TODO
	return nil, nil
}
