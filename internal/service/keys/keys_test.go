package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	keysRepository "simple_server_oauth2/internal/repository/keys"
)

func Test_GetPublicKeys(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	keysRepo := keysRepository.NewKeysStore(logger)
	s := keysService{
		keysStore: keysRepo,
		logger:    logger,
	}

	clientId := "client-one"

	noKeys, errNoKeys := s.GetPublicKeys(context.Background(), clientId)
	require.NoError(t, errNoKeys)
	assert.Equal(t, 0, len(noKeys))

	kid1 := uuid.NewString()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	errSave := s.SaveKey(clientId, kid1, *key)
	require.NoError(t, errSave)

	keys, errGet := s.GetPublicKeys(context.Background(), clientId)
	require.NoError(t, errGet)
	assert.Equal(t, 1, len(keys))

	clientId2 := "client-two"
	kid2 := uuid.NewString()
	key2, err2 := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err2)
	errSave2 := s.SaveKey(clientId2, kid2, *key2)
	require.NoError(t, errSave2)

	keys, errGet = s.GetPublicKeys(context.Background(), clientId2)
	require.NoError(t, errGet)
	assert.Equal(t, 1, len(keys))

	kid3 := uuid.NewString()
	key3, err3 := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err3)
	errSave3 := s.SaveKey(clientId2, kid3, *key3)
	require.NoError(t, errSave3)

	keys, errGet = s.GetPublicKeys(context.Background(), clientId2)
	require.NoError(t, errGet)
	assert.Equal(t, 2, len(keys))
}

func Test_GetPublicKey(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	keysRepo := keysRepository.NewKeysStore(logger)
	s := keysService{
		keysStore: keysRepo,
		logger:    logger,
	}

	clientId := "client-one"
	kid := uuid.NewString()

	noKey, errNoKey := s.GetPublicKey(clientId, kid)
	require.Error(t, errNoKey)
	assert.Nil(t, noKey)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	errSave := s.SaveKey(clientId, kid, *key)
	require.NoError(t, errSave)

	publicKey, errGet := s.GetPublicKey(clientId, kid)
	require.NoError(t, errGet)
	require.NotNil(t, publicKey)
	assert.Equal(t, key.Public(), publicKey)
}
