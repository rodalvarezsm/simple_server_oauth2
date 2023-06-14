package keys

import (
	"context"
	"crypto"
	"crypto/rsa"

	"github.com/lestrrat-go/jwx/jwk"
	"go.uber.org/zap"

	keysRepository "simple_server_oauth2/internal/repository/keys"
	"simple_server_oauth2/internal/service"
)

type keysService struct {
	keysStore keysRepository.KeysStore
	logger    *zap.Logger
}

func NewService(keysStore keysRepository.KeysStore, logger *zap.Logger) service.KeysService {
	return &keysService{
		keysStore: keysStore,
		logger:    logger,
	}
}

func (k *keysService) GetPublicKeys(ctx context.Context, clientId string) ([]jwk.Key, error) {
	keys, err := k.keysStore.GetPublicKeys(ctx, clientId)
	return keys, err
}

func (k *keysService) SaveKey(clientId, kid string, key rsa.PrivateKey) error {
	err := k.keysStore.SaveKey(clientId, kid, key)
	if err != nil {
		k.logger.Error("could not store a key", zap.Error(err))
		return err
	}
	return nil
}

func (k *keysService) GetPublicKey(clientId, kid string) (crypto.PublicKey, error) {
	key, err := k.keysStore.GetPublicKey(clientId, kid)
	if err != nil {
		return nil, err
	}
	return key, nil
}
