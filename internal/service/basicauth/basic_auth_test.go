package basicauth

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	credentialsRepository "simple_server_oauth2/internal/repository/credentials"
	"simple_server_oauth2/internal/service/credentials"
)

func Test_parseBasicAuth(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name         string
		args         args
		wantUsername string
		wantPassword string
		wantError    bool
	}{
		{
			name:         "correct",
			args:         args{s: "Basic " + encodeBase64("user:pass")},
			wantUsername: "user",
			wantPassword: "pass",
			wantError:    false,
		},
		{
			name:      "credentials are empty string",
			args:      args{s: "Basic " + encodeBase64("")},
			wantError: true,
		},
		{
			name:      "missing prefix",
			args:      args{s: encodeBase64("user:pass")},
			wantError: true,
		},
		{
			name:      "not base64 encoded",
			args:      args{s: "Basic ABCDEFG=="},
			wantError: true,
		},
		{
			name:      "missing username",
			args:      args{s: "Basic " + encodeBase64(":pass")},
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUsername, gotPassword, err := parseBasicAuth(tt.args.s)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantUsername, gotUsername)
			assert.Equal(t, tt.wantPassword, gotPassword)
		})
	}
}

func TestService_Authenticate(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	credsRepo := credentialsRepository.NewCredentialsStore(logger)
	credentials := credentials.NewCredentialsService(credsRepo, logger)
	s := NewService(credentials, logger)

	authenticate, err := s.Authenticate(context.Background(), "usertest", "passtest")
	assert.NoError(t, err)
	assert.True(t, authenticate)
}

func TestService_Authenticate_No_Credentials_Found(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	credsRepo := credentialsRepository.NewCredentialsStore(logger)
	credentials := credentials.NewCredentialsService(credsRepo, logger)
	s := NewService(credentials, logger)

	authenticate, err := s.Authenticate(context.Background(), "wrong-user", "passtest")
	assert.Error(t, err)
	assert.False(t, authenticate)
}

func TestService_Authenticate_Wrong_Password(t *testing.T) {
	core, _ := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)

	credsRepo := credentialsRepository.NewCredentialsStore(logger)
	credentials := credentials.NewCredentialsService(credsRepo, logger)
	s := NewService(credentials, logger)

	authenticate, err := s.Authenticate(context.Background(), "usertest", "wrong-pass")
	assert.Error(t, err)
	assert.False(t, authenticate)
}

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
