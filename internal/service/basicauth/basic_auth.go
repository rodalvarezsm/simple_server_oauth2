package basicauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"simple_server_oauth2/internal/service"
)

type Service struct {
	credentials service.CredentialsService
	logger      *zap.Logger
}

func NewService(credentials service.CredentialsService, logger *zap.Logger) *Service {
	return &Service{
		credentials: credentials,
		logger:      logger,
	}
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (bool, error) {
	creds, err := s.credentials.GetCredentials(ctx, username)
	if err != nil {
		s.logger.Error("get credentials failed", zap.Error(err))
		return false, errors.Wrap(err, "get credentials failed")
	}

	if creds == nil {
		s.logger.Warn("no credentials found")
		return false, fmt.Errorf("get credentials failed: no credentials found")
	}

	// TODO: password should be hashed
	if password == creds.Password {
		return true, nil
	}
	return false, fmt.Errorf("credentials do not match")
}

func (s *Service) ParseBasicAuthCredentials(credentials string) (username, password string, err error) {
	user, pwd, errParsing := parseBasicAuth(credentials)
	if errParsing != nil {
		return "", "", errors.Wrap(errParsing, "parse credentials failed")
	}
	return user, pwd, nil
}

func parseBasicAuth(s string) (username, password string, err error) {
	if !strings.HasPrefix(s, "Basic ") {
		return "", "", fmt.Errorf("value must start with 'Basic '")
	}
	s = strings.TrimLeft(s, "Basic ")

	decoded, errDecode := base64.StdEncoding.DecodeString(s)
	if errDecode != nil {
		return "", "", errors.Wrap(errDecode, "decode failed")
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 || creds[0] == "" || creds[1] == "" {
		return "", "", fmt.Errorf("credentials are not correctly formatted")
	}

	return creds[0], creds[1], nil
}
