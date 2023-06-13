package basicauth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
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

func encodeBase64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
