package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
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
	keys, errKeys := h.service.GetPublicKeys(c, c.Value(ClientId).(string))
	if errKeys != nil {
		c.JSON(http.StatusInternalServerError, "failed getting the list of keys")
		return
	}
	if keys == nil {
		keys = []jwk.Key{}
	}
	c.JSON(http.StatusOK, keys)
	return

}
