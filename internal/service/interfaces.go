package service

import (
	"context"
	"crypto"
	"crypto/rsa"
	"time"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"

	"simple_server_oauth2/internal/model"
)

type JWTService interface {
	// NewToken receives a user id and returns a signed token, expiration date or and error if the token cannot be created.
	NewToken(user string) (string, *time.Time, error)
	// VerifyJWT verifies if the token is valid for the clientId
	VerifyJWT(token, clientId string) (*gojwt.Token, error)
}

type Auth interface {
	// Authenticate verifies if the received credentials are registered in the app
	Authenticate(ctx context.Context, username, password string) (bool, error)
	// ParseBasicAuthCredentials expects the value of the Authorization header for Basic Authentication and returns the parsed credentials
	ParseBasicAuthCredentials(credentials string) (username, password string, err error)
}

type CredentialsService interface {
	// GetCredentials returns the stored credentials for the received username
	GetCredentials(ctx context.Context, username string) (*model.Credentials, error)
}

type KeysService interface {
	// GetPublicKeys returns all public keys for the clientId received
	GetPublicKeys(ctx context.Context, clientId string) ([]jwk.Key, error)
	// SaveKey stores the received key and kid for the clientId
	SaveKey(clientId, kid string, key rsa.PrivateKey) error
	// GetPublicKey returns the public key for assigned to the clientId and identified by the key id
	GetPublicKey(clientId, kid string) (crypto.PublicKey, error)
}
