package jwt

import (
	"testing"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	keysRepository "simple_server_oauth2/internal/repository/keys"
	"simple_server_oauth2/internal/service/keys"
)

func TestService_VerifyJWT(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	keysRepo := keysRepository.NewKeysStore(logger)
	keysService := keys.NewService(keysRepo, logger)
	s := Service{
		keysService: keysService,
		logger:      logger,
	}

	token, expiry, err := s.NewToken("test-user")
	assert.NoError(t, err)

	verifiedToken, errVerify := s.VerifyJWT(token, "test-user")
	assert.NoError(t, errVerify)

	claims1, ok := verifiedToken.Claims.(gojwt.MapClaims)
	assert.True(t, ok)

	claimExp, okExp := claims1["exp"]
	require.True(t, okExp)
	assert.Equal(t, claimExp, float64(expiry.Unix()))
}

func TestService_VerifyJWT_Error(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	keysRepo := keysRepository.NewKeysStore(logger)
	keysService := keys.NewService(keysRepo, logger)
	s := Service{
		keysService: keysService,
		logger:      logger,
	}

	// create token
	token, _, err := s.NewToken("test-user")
	assert.NoError(t, err)

	// try to verify a bad token
	_, errVerify := s.VerifyJWT("token", "test-user")
	assert.Error(t, errVerify)

	// try to verify a good token but for another client
	_, errIntro := s.VerifyJWT(token, "wrong-user")
	assert.Error(t, errIntro)
}
