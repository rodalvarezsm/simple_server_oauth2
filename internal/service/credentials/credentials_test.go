package credentials

import (
	"context"
	"testing"

	"github.com/alexedwards/argon2id"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	credentialsRepository "simple_server_oauth2/internal/repository/credentials"
)

func TestCredentialsService_GetCredentials(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	credsRepo := credentialsRepository.NewCredentialsStore(logger)
	credentials := NewCredentialsService(credsRepo, logger)

	t.Run("no credentials for the user", func(t *testing.T) {
		getCredentials, err := credentials.GetCredentials(context.Background(), "wrong-user")
		assert.NoError(t, err)
		assert.Nil(t, getCredentials)
	})

	t.Run("credentials found for the user", func(t *testing.T) {
		getCredentials, err := credentials.GetCredentials(context.Background(), "usertest")
		assert.NoError(t, err)
		require.NotNil(t, getCredentials)
		assert.Equal(t, "usertest", getCredentials.Username)
		match, errCompare := argon2id.ComparePasswordAndHash("passtest", getCredentials.Password)
		assert.NoError(t, errCompare)
		assert.True(t, match)
	})
}
