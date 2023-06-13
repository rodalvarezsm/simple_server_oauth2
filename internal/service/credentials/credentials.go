package credentials

import (
	"context"

	"go.uber.org/zap"

	credentialsRepository "simple_server_oauth2/internal/repository/credentials"

	"simple_server_oauth2/internal/model"
	"simple_server_oauth2/internal/service"
)

type credentialsService struct {
	credentialsStore credentialsRepository.CredentialsStore
	logger           *zap.Logger
}

func NewCredentialsService(credStore credentialsRepository.CredentialsStore, logger *zap.Logger) service.CredentialsService {
	return &credentialsService{
		credentialsStore: credStore,
		logger:           logger,
	}
}

func (c *credentialsService) GetCredentials(ctx context.Context, username string) (*model.Credentials, error) {
	return c.credentialsStore.GetCredentialsByUsername(ctx, username)
}
