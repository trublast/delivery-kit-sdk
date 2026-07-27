package hashivault

import (
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLoginDoesNotLeakHostToken proves that when the SDK auto-loads a host
// VAULT_TOKEN at client construction, that token never appears in the
// X-Vault-Token header of a login request. The leak path is that
// baseAuthenticator.login writes to /auth/<path>/login before SetToken, so an
// un-cleared host token would be attached to that first request. AppRole and
// JWT (static and GitHub Actions OIDC) all funnel through baseAuthenticator.login,
// so covering AppRole and static JWT exercises the shared leak path.
func TestLoginDoesNotLeakHostToken(t *testing.T) {
	const hostToken = "host-token-must-not-leak"
	const keyResourceID = "hashivault://transit-key"

	tests := []struct {
		name          string
		wantLoginPath string
		newAuth       func() authenticator
	}{
		{
			name:          "approle",
			wantLoginPath: "/v1/auth/ar/login",
			newAuth: func() authenticator {
				return newAppRoleAuthenticator("role-id", "secret-id", "")
			},
		},
		{
			name:          "static jwt",
			wantLoginPath: "/v1/auth/jwt/login",
			newAuth: func() authenticator {
				return newJWTAuthenticator(newStaticJwtTokenProvider("static-jwt"), "jwt-role", "")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			t.Setenv("VAULT_TOKEN", hostToken)

			var gotHeader string
			var gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotHeader = r.Header.Get("X-Vault-Token")
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "new-vault-token",
						"lease_duration": 3600,
					},
				})
			}))
			defer srv.Close()

			client, err := newHashivaultClient(tt.newAuth(), srv.URL, "transit", keyResourceID, 0, crypto.SHA256)
			if err != nil {
				t.Fatalf("newHashivaultClient() unexpected error: %v", err)
			}

			if got := client.client.Token(); got != "" {
				t.Fatalf("client token after construction = %q, want empty (host token must be cleared)", got)
			}

			if err := client.auth.Login(client.client); err != nil {
				t.Fatalf("Login() unexpected error: %v", err)
			}

			if gotPath != tt.wantLoginPath {
				t.Fatalf("login request path = %q, want %q", gotPath, tt.wantLoginPath)
			}
			if gotHeader == hostToken {
				t.Errorf("login request leaked host token in X-Vault-Token header: %q", gotHeader)
			}
			if gotHeader != "" {
				t.Errorf("login request X-Vault-Token = %q, want empty", gotHeader)
			}
			if got := client.client.Token(); got != "new-vault-token" {
				t.Errorf("client token after login = %q, want %q", got, "new-vault-token")
			}
		})
	}
}
