package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/controller"
	credentialsRepo "simple_server_oauth2/internal/repository/credentials"
	keysRepository "simple_server_oauth2/internal/repository/keys"
	"simple_server_oauth2/internal/service/basicauth"
	"simple_server_oauth2/internal/service/credentials"
	"simple_server_oauth2/internal/service/jwt"
	"simple_server_oauth2/internal/service/keys"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Errorf("unable to load zap logger, error: %v", err))
	}

	r := gin.Default()
	credRepo := credentialsRepo.NewCredentialsStore(logger)
	credService := credentials.NewCredentialsService(credRepo, logger)
	basicAuthService := basicauth.NewService(credService, logger)
	keysRepo := keysRepository.NewKeysStore(logger)
	keysService := keys.NewService(keysRepo, logger)
	jwtService := jwt.NewService(keysService, logger)
	controller.NewJwtHandler(jwtService, basicAuthService, r, logger)

	err = r.Run()
	if err != nil {
		panic(fmt.Errorf("unable to load gin engine, error: %v", err))
	}
}
