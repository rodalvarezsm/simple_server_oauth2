package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/service"
)

type Service struct {
	keysService service.KeysService
	logger      *zap.Logger
}

type customClaims struct {
	ClientId string `json:"clientId"`
	gojwt.StandardClaims
}

func NewService(keysService service.KeysService, logger *zap.Logger) service.JWTService {
	return &Service{
		keysService: keysService,
		logger:      logger,
	}
}

func (s *Service) NewToken(username string) (string, *time.Time, error) {
	token, expiry, err := s.generateJWT(username)
	if err != nil {
		return "", nil, err
	}

	return token, expiry, nil
}

func (s *Service) generateJWT(user string) (string, *time.Time, error) {
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
		return "", nil, err
	}

	kid := uuid.NewString()
	token.Header["kid"] = kid

	signedToken, errSign := token.SignedString(key)
	if errSign != nil {
		log.Print(err, "error signing token")
		return "", nil, err
	}

	err = s.keysService.SaveKey(user, kid, *key)
	if err != nil {
		return "", nil, err
	}
	return signedToken, &expiry, nil
}

func (s *Service) VerifyJWT(t, clientId string) (*gojwt.Token, error) {
	token, err := gojwt.Parse(t, func(token *gojwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*gojwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unauthorized")
		}
		kid, found := token.Header["kid"]
		if !found {
			return nil, fmt.Errorf("kid not found in token")
		}
		keyId, ok := kid.(string)
		if !ok {
			return nil, fmt.Errorf("convert token to string failed")
		}
		claims := token.Claims.(gojwt.MapClaims)
		clientClaim, okClientClaim := claims["sub"]
		if !okClientClaim {
			return nil, fmt.Errorf("clientId not found in token")
		}
		clientInfo, okClientId := clientClaim.(string)
		if !okClientId {
			return nil, fmt.Errorf("convert clientId to string failed")
		}
		key, err := s.keysService.GetPublicKey(clientInfo, keyId)
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return token, fmt.Errorf("unauthorized")
	}
	tokenClaims := token.Claims.(gojwt.MapClaims)
	clientFromToken := tokenClaims["sub"].(string)
	if clientFromToken != clientId {
		return token, fmt.Errorf("token belongs to another clientId")
	}
	return token, nil
}
