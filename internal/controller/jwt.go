package controller

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	jsoniter "github.com/json-iterator/go"
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

type InstrospectionRequest struct {
	Token string `json:"token" binding:"required"`
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

		c.JSON(http.StatusOK, buildTokenResponse(token, *expiry))
		return
	}
}

func (h *JWTHandler) introspect(c *gin.Context) {
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

	_, errAuth := h.basicAuth.Authenticate(c, username, password)
	if errAuth != nil {
		h.logger.Error("failed to authenticate credentials", zap.Error(err))
		c.JSON(http.StatusUnauthorized, "access not authorized")
		return
	}

	var request InstrospectionRequest
	err = jsoniter.NewDecoder(c.Request.Body).Decode(&request)
	if err != nil {
		h.logger.Error("failed to decode request body", zap.Error(err))
		c.JSON(http.StatusBadRequest, "request body could not be decoded")
		return
	}

	jwt, errVerify := h.service.VerifyJWT(request.Token, username)
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
