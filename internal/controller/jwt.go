package controller

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/model"
	"simple_server_oauth2/internal/service"
)

const ClientId = "clientId"

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

	e.POST("/token", h.generateJWT)
	e.POST("/token_info", h.introspect)

	return h
}

func (h *JWTHandler) generateJWT(c *gin.Context) {
	token, expiry, errToken := h.service.NewToken(c.Value(ClientId).(string))
	if errToken != nil {
		c.JSON(http.StatusInternalServerError, "failed creating a token")
		return
	}

	c.JSON(http.StatusOK, buildTokenResponse(token, *expiry))
	return

}

func (h *JWTHandler) introspect(c *gin.Context) {
	if c.Request.Body == nil {
		h.logger.Error("introspect endpoint received an empty request body")
		c.JSON(http.StatusBadRequest, "request body cannot be empty")
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		h.logger.Error("introspect endpoint could not read the request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, "request body could not be read")
		return
	}
	param := string(body)
	bodyData := strings.Split(param, "=")
	if len(bodyData) != 2 || bodyData[0] != "token" {
		h.logger.Error(fmt.Sprintf("introspect endpoint could not read the token from the body: %s", param))
		c.JSON(http.StatusBadRequest, "request body must include a token")
		return
	}

	jwt, errVerify := h.service.VerifyJWT(bodyData[1], c.Value(ClientId).(string))
	if errVerify != nil {
		h.logger.Error("token verification failed", zap.Error(errVerify))
		c.JSON(http.StatusOK, buildInactiveResponse())
		return
	}
	c.JSON(http.StatusOK, buildIntrospectResponse(jwt))
	return
}

func buildTokenResponse(token string, expiry time.Time) model.TokenResponse {
	return model.TokenResponse{
		AccessToken: token,
		Scope:       "all",
		TokenType:   "Bearer",
		Expiry:      expiry.String(),
	}
}

func buildIntrospectResponse(token *jwt.Token) model.IntrospectionResponse {
	claims := token.Claims.(jwt.MapClaims)
	exp := claims["exp"]
	expiry := int64(exp.(float64))
	active := expiry > time.Now().Unix()
	if !active {
		return buildInactiveResponse()
	}
	clientFromToken := claims["sub"].(string)
	return model.IntrospectionResponse{
		Active:   active,
		ClientId: clientFromToken,
		Expiry:   expiry,
	}
}

func buildInactiveResponse() model.IntrospectionResponse {
	return model.IntrospectionResponse{Active: false}
}
