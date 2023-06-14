package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/service"
)

func BasicAuthentication(basicAuth service.Auth, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req HeaderAuthorization
		if err := c.ShouldBindHeader(&req); err != nil {
			logger.Error("parse request failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, "access not authorized")
			return
		}

		username, password, err := basicAuth.ParseBasicAuthCredentials(req.Authorization)
		if err != nil {
			logger.Error("failed to parse credentials", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, "access not authorized")
			return
		}

		_, errAuth := basicAuth.Authenticate(c, username, password)
		if errAuth != nil {
			logger.Error("failed to authenticate credentials", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusUnauthorized, "access not authorized")
			return
		}

		c.Set(CLIENT_ID, username)

		c.Next()
	}
}
