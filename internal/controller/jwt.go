package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
	"simple_server_oauth2/internal/service"
)

type JWTHandler struct {
	service   service.JWTService
	basicAuth service.Auth
	logger    *zap.Logger
}

type HeaderAuthorization struct {
	Authorization string `header:"Authorization" binding:"required,startswith=Basic "`
}

func NewJwtHandler(s service.JWTService, b service.Auth, e *gin.Engine, l *zap.Logger) *JWTHandler {
	h := &JWTHandler{
		service:   s,
		basicAuth: b,
		logger:    l,
	}

	e.GET("/token", h.generateJWT)

	return h
}

func (h *JWTHandler) generateJWT(c *gin.Context) {
	var req HeaderAuthorization
	if err := c.ShouldBindHeader(&req); err != nil {
		h.logger.Error("parse request failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, "access not authorized")
		return
	}

	username, password, err := h.basicAuth.ParseBasicAuthCredentials(req.Authorization)
	if err != nil {
		h.logger.Error("failed to parse credentials", zap.Error(err))
		c.JSON(http.StatusUnauthorized, "access not authorized")
		return
	}

	authenticated, errAuth := h.basicAuth.Authenticate(c, username, password)
	if errAuth != nil {
		h.logger.Error("failed to authenticate credentials", zap.Error(err))
		c.JSON(http.StatusUnauthorized, "access not authorized")
		return
	}

	if authenticated {
		token, expiry, errToken := h.service.NewToken(username)
		if errToken != nil {
			c.JSON(http.StatusInternalServerError, "failed creating a token")
			return
		}

		c.JSON(http.StatusOK, buildResponse(token, *expiry))
		return
	}
}

func buildResponse(token string, expiry time.Time) model.TokenResponse {
	return model.TokenResponse{
		AccessToken: token,
		Scope:       "all",
		TokenType:   "Bearer",
		Expiry:      expiry.String(),
	}
}
