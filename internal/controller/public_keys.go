package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/service"
)

type PublicKeysHandler struct {
	service   service.KeysService
	basicAuth service.Auth
	logger    *zap.Logger
}

func NewPublicKeysHandler(s service.KeysService, b service.Auth, e *gin.Engine, l *zap.Logger) *PublicKeysHandler {
	h := &PublicKeysHandler{
		service:   s,
		basicAuth: b,
		logger:    l,
	}

	e.POST("/jwks", h.getPublicKeys)

	return h
}

func (h *PublicKeysHandler) getPublicKeys(c *gin.Context) {
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
		keys, errKeys := h.service.GetPublicKeys(c, username)
		if errKeys != nil {
			c.JSON(http.StatusInternalServerError, "failed getting the list of keys")
			return
		}

		c.JSON(http.StatusOK, keys)
		return
	}
}
