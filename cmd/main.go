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

	e := gin.Default()
	credRepo := credentialsRepo.NewCredentialsStore(logger)
	credService := credentials.NewCredentialsService(credRepo, logger)
	basicAuthService := basicauth.NewService(credService, logger)
	e.Use(controller.BasicAuthentication(basicAuthService, logger))
	keysRepo := keysRepository.NewKeysStore(logger)
	keysService := keys.NewService(keysRepo, logger)
	jwtService := jwt.NewService(keysService, logger)
	controller.NewJwtHandler(jwtService, basicAuthService, e, logger)
	controller.NewPublicKeysHandler(keysService, basicAuthService, e, logger)

	err = e.Run()
	if err != nil {
		panic(fmt.Errorf("unable to load gin engine, error: %v", err))
	}
}
