package keys

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
)

type KeysStore interface {
	GetPublicKeys(ctx context.Context, clientId string) ([]jwk.Key, error)
	SaveKey(clientId, kid string, key rsa.PrivateKey) error
	GetPublicKey(clientId, kid string) (crypto.PublicKey, error)
}

type keysStore struct {
	memoryStore map[string][]model.Key
	logger      *zap.Logger
}

func NewKeysStore(logger *zap.Logger) KeysStore {
	return &keysStore{
		memoryStore: map[string][]model.Key{},
		logger:      logger,
	}
}

func (k *keysStore) GetPublicKeys(ctx context.Context, clientId string) ([]jwk.Key, error) {
	var publicKeys []jwk.Key
	if items, found := k.memoryStore[clientId]; found {
		for _, item := range items {
			key, err := jwk.New(item.RSAKey)
			if err != nil {
				return nil, err
			}
			publicKeys = append(publicKeys, key)
		}
		return publicKeys, nil
	}
	return publicKeys, nil
}

func (k *keysStore) SaveKey(clientId, kid string, key rsa.PrivateKey) error {
	newKey := model.Key{
		Kid:    kid,
		RSAKey: key,
	}
	if _, found := k.memoryStore[clientId]; !found {
		k.memoryStore[clientId] = []model.Key{newKey}
		return nil
	}
	k.memoryStore[clientId] = append(k.memoryStore[clientId], newKey)
	return nil
}

func (k *keysStore) GetPublicKey(clientId, kid string) (crypto.PublicKey, error) {
	if _, found := k.memoryStore[clientId]; !found {
		return nil, fmt.Errorf("could not find public key")
	}
	for _, keyData := range k.memoryStore[clientId] {
		if keyData.Kid == kid {
			return keyData.RSAKey.Public(), nil
		}
	}
	return nil, fmt.Errorf("could not find public key")
}
