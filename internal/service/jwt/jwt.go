package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/service"
)

// TODO use RSA key
var secretKey = []byte("l9KpsdafjPkdafjdsalfmnSQvfgsg0oierpsnvs")

type Service struct {
	logger *zap.Logger
}

func NewService(logger *zap.Logger) service.JWTService {
	return &Service{
		logger: logger,
	}
}

func (s *Service) New(username string) (string, error) {
	token, _, err := s.generateJWT(username)
	if err != nil {
		return "", err
	}

	return token, nil
}

func generateJWT(user string) (string, error) {
	expiry := time.Now().UTC().Add(time.Hour)
	claims := map[string]interface{}{
		"iat": time.Now().UTC().Add(-10 * time.Second).Unix(),
		"exp": expiry.Unix(),
		"jti": uuid.NewString(),
		"sub": user,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(claims))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	// TODO add kid to the token
	kid := uuid.NewString()
	token.Header["kid"] = kid

	// should sign with public or private key?
	signedToken, err := token.SignedString(key)
	if err != nil {
		log.Print(err, "error signing token")
		return "", err
	}

	return signedToken, nil
}
