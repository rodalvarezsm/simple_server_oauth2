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
	keys, errKeys := h.service.GetPublicKeys(c, c.Value(CLIENT_ID).(string))
	if errKeys != nil {
		c.JSON(http.StatusInternalServerError, "failed getting the list of keys")
		return
	}

	c.JSON(http.StatusOK, keys)
	return

}
