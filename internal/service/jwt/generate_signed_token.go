package jwt

import (
	"log"
	"time"

	gojwt "github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var secretKey = []byte("l9KpsdafjPkdafjdsalfmnSQvfgsg0oierpsnvs")

func generateJWT(user string) (string, error) {
	expiry := time.Now().UTC().Add(time.Hour)
	claims := map[string]interface{}{
		"iat": time.Now().UTC().Add(-10 * time.Second).Unix(),
		"exp": expiry.Unix(),
		"jti": uuid.NewString(),
		"sub": user,
	}

	token := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims(claims))

	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		log.Print(err, "error signing token")
		return "", err
	}

	return signedToken, nil
}
