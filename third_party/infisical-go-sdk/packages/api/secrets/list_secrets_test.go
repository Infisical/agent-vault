package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-resty/resty/v2"
	sdkErrors "github.com/infisical/go-sdk/packages/errors"
	"github.com/infisical/go-sdk/packages/models"
)

func newTestClient(t *testing.T, handler http.Handler) *resty.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return resty.New().SetBaseURL(server.URL)
}

func jsonHandler(statusCode int, etag string, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
}

func TestCallListSecretsV3(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		etag          string
		responseBody  any
		request       ListSecretsV3RawRequest
		wantErr       bool
		checkErr      func(error) bool
		wantSecretLen int
		wantFirstKey  string
		wantETag      string
	}{
		{
			name:       "success with secrets",
			statusCode: http.StatusOK,
			responseBody: ListSecretsV3RawResponse{
				Secrets: []models.Secret{
					{SecretKey: "DB_HOST", SecretValue: "localhost"},
					{SecretKey: "DB_PORT", SecretValue: "5432"},
				},
			},
			request:       ListSecretsV3RawRequest{ProjectID: "proj-123", Environment: "dev", SecretPath: "/"},
			wantSecretLen: 2,
			wantFirstKey:  "DB_HOST",
		},
		{
			name:       "etag populated from response header",
			statusCode: http.StatusOK,
			etag:       `"abc123"`,
			responseBody: ListSecretsV3RawResponse{
				Secrets: []models.Secret{{SecretKey: "KEY", SecretValue: "val"}},
			},
			request:       ListSecretsV3RawRequest{ProjectID: "proj-123", Environment: "dev"},
			wantSecretLen: 1,
			wantETag:      `"abc123"`,
		},
		{
			name:       "304 not modified returns NotModifiedError",
			statusCode: http.StatusNotModified,
			request:    ListSecretsV3RawRequest{ProjectID: "proj-123", Environment: "dev", IfNoneMatch: `"abc123"`},
			wantErr:    true,
			checkErr:   func(err error) bool { var target *sdkErrors.NotModifiedError; return errors.As(err, &target) },
		},
		{
			name:         "403 forbidden returns APIError",
			statusCode:   http.StatusForbidden,
			responseBody: map[string]string{"message": "access denied"},
			request:      ListSecretsV3RawRequest{ProjectID: "proj-123", Environment: "dev"},
			wantErr:      true,
			checkErr:     func(err error) bool { var target *sdkErrors.APIError; return errors.As(err, &target) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newTestClient(t, jsonHandler(tt.statusCode, tt.etag, tt.responseBody))

			res, err := CallListSecretsV3(nil, client, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.checkErr != nil && !tt.checkErr(err) {
					t.Errorf("error type check failed, got %T: %v", err, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(res.Secrets) != tt.wantSecretLen {
				t.Errorf("expected %d secrets, got %d", tt.wantSecretLen, len(res.Secrets))
			}
			if tt.wantFirstKey != "" && len(res.Secrets) > 0 && res.Secrets[0].SecretKey != tt.wantFirstKey {
				t.Errorf("expected first key %s, got %s", tt.wantFirstKey, res.Secrets[0].SecretKey)
			}
			if tt.wantETag != "" && res.ETag != tt.wantETag {
				t.Errorf("expected ETag %s, got %s", tt.wantETag, res.ETag)
			}
		})
	}
}
