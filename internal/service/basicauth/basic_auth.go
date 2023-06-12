package basic_auth

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

func (s *Service) ParseCredentials(credentials string) (username string, password string, err error) {
	user, pwd, errCurr := parseBasicAuth(credentials)
	if errCurr != nil {
		return "", "", errors.Http(http.StatusUnauthorized, "parse credentials failed").WithError(errCurr).NoStack()
	}
	return user, pwd, nil
}

func parseBasicAuth(s string) (username string, password string, err error) {
	if !strings.HasPrefix(s, "Basic ") {
		return "", "", errors.Wrap(fmt.Errorf("don't have 'Basic ' prefix"))
	}
	s = strings.TrimLeft(s, "Basic ")

	payload, ierr := base64.StdEncoding.DecodeString(s)
	if ierr != nil {
		return "", "", errors.Wrap(fmt.Errorf("decode failed: %v", ierr))
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 || pair[0] == "" || pair[1] == "" {
		return "", "", errors.Wrap(fmt.Errorf("wrong credentials"))
	}

	return pair[0], pair[1], nil
}
