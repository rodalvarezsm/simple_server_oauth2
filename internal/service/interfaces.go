package service

import (
	"context"
	"crypto"
	"crypto/rsa"
	"time"

	"simple_server_oauth2/internal/model"
)

type JWTService interface {
	NewToken(user string) (string, *time.Time, error)
}

type Auth interface {
	Authenticate(ctx context.Context, username, password string) (bool, error)
	ParseBasicAuthCredentials(credentials string) (username, password string, err error)
}

type CredentialsService interface {
	GetCredentials(ctx context.Context, username string) (*model.Credentials, error)
}

type KeysService interface {
	GetPublicKeys(ctx context.Context, clientId string) ([]model.Key, error)
	SaveKey(clientId, kid string, key rsa.PrivateKey) error
	GetPublicKey(clientId, kid string) (crypto.PublicKey, error)
}
