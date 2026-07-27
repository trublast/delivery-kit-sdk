package hashivault

import (
	"os"
	"strings"
	"testing"

	vault "github.com/hashicorp/vault/api"
)

var vaultEnvKeys = []string{
	"WERF_VAULT_AUTH_ROLE_ID", "VAULT_ROLE_ID",
	"WERF_VAULT_AUTH_SECRET_ID", "VAULT_SECRET_ID",
	"WERF_VAULT_AUTH_ROLE",
	"WERF_VAULT_AUTH_JWT",
	"WERF_VAULT_AUTH_PATH",
	"WERF_ACTIONS_AUDIENCE",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"VAULT_TOKEN",
}

// clearVaultEnv isolates a test from any Vault-related environment variables
// that may be present in the host or CI environment. Variables are unset (not
// set to an empty string) because getters chain WERF_* over VAULT_* via
// os.LookupEnv, where an empty-but-present value would mask the fallback.
func clearVaultEnv(t *testing.T) {
	t.Helper()
	// t.Setenv registers restoration of the original values on cleanup and
	// guards against parallel tests; unset afterwards to get a truly empty env.
	for _, key := range vaultEnvKeys {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}
}

func assertAppRole(t *testing.T, auth authenticator, wantRole, wantSecret, wantPath string) {
	t.Helper()
	a, ok := auth.(*appRoleAuthenticator)
	if !ok {
		t.Fatalf("expected *appRoleAuthenticator, got %T", auth)
	}
	if a.roleID != wantRole {
		t.Errorf("roleID = %q, want %q", a.roleID, wantRole)
	}
	if a.secretID != wantSecret {
		t.Errorf("secretID = %q, want %q", a.secretID, wantSecret)
	}
	if a.authPath != wantPath {
		t.Errorf("authPath = %q, want %q", a.authPath, wantPath)
	}
}

func assertOIDC(t *testing.T, auth authenticator, wantRole, wantPath string) {
	t.Helper()
	a, ok := auth.(*jwtAuthenticator)
	if !ok {
		t.Fatalf("expected *jwtAuthenticator, got %T", auth)
	}
	if _, ok := a.jwtProvider.(*actionsOidcJwtTokenProvider); !ok {
		t.Fatalf("expected *actionsOidcJwtTokenProvider, got %T", a.jwtProvider)
	}
	if a.role != wantRole {
		t.Errorf("role = %q, want %q", a.role, wantRole)
	}
	if a.authPath != wantPath {
		t.Errorf("authPath = %q, want %q", a.authPath, wantPath)
	}
}

func assertStaticJWT(t *testing.T, auth authenticator, wantRole, wantPath string) {
	t.Helper()
	a, ok := auth.(*jwtAuthenticator)
	if !ok {
		t.Fatalf("expected *jwtAuthenticator, got %T", auth)
	}
	if _, ok := a.jwtProvider.(*staticJwtTokenProvider); !ok {
		t.Fatalf("expected *staticJwtTokenProvider, got %T", a.jwtProvider)
	}
	if a.role != wantRole {
		t.Errorf("role = %q, want %q", a.role, wantRole)
	}
	if a.authPath != wantPath {
		t.Errorf("authPath = %q, want %q", a.authPath, wantPath)
	}
}

func assertStaticToken(t *testing.T, auth authenticator, wantToken string) {
	t.Helper()
	a, ok := auth.(*staticAuthenticator)
	if !ok {
		t.Fatalf("expected *staticAuthenticator, got %T", auth)
	}
	if a.tokenID != wantToken {
		t.Errorf("tokenID = %q, want %q", a.tokenID, wantToken)
	}
}

// TestNewAuthenticatorEnv covers the env-driven auth source: when VaultOpts
// carries no auth field, the method is selected from environment variables,
// following the priority AppRole > GitHub Actions OIDC > static JWT > token.
func TestNewAuthenticatorEnv(t *testing.T) {
	tests := []struct {
		name   string
		env    map[string]string
		verify func(*testing.T, authenticator)
	}{
		{
			name: "approle from env wins over other methods",
			env: map[string]string{
				"VAULT_ROLE_ID":         "env-role",
				"VAULT_SECRET_ID":       "env-secret",
				"WERF_ACTIONS_AUDIENCE": "aud",
				"WERF_VAULT_AUTH_JWT":   "jwt-token",
			},
			verify: func(t *testing.T, a authenticator) { assertAppRole(t, a, "env-role", "env-secret", "ar") },
		},
		{
			name: "oidc from env when approle absent",
			env: map[string]string{
				"WERF_ACTIONS_AUDIENCE":          "my-audience",
				"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://example.com/token",
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
				"WERF_VAULT_AUTH_ROLE":           "ci-role",
				"WERF_VAULT_AUTH_JWT":            "jwt-token",
			},
			verify: func(t *testing.T, a authenticator) { assertOIDC(t, a, "ci-role", "jwt") },
		},
		{
			name: "static jwt from env when approle and oidc absent",
			env: map[string]string{
				"WERF_VAULT_AUTH_JWT":  "my-jwt",
				"WERF_VAULT_AUTH_ROLE": "jwt-role",
			},
			verify: func(t *testing.T, a authenticator) { assertStaticJWT(t, a, "jwt-role", "jwt") },
		},
		{
			name: "token fallback from env when no auth method configured",
			env: map[string]string{
				"VAULT_TOKEN": "env-static-token",
			},
			verify: func(t *testing.T, a authenticator) { assertStaticToken(t, a, "env-static-token") },
		},
		{
			name: "auth path from env applies to approle",
			env: map[string]string{
				"VAULT_ROLE_ID":        "env-role",
				"VAULT_SECRET_ID":      "env-secret",
				"WERF_VAULT_AUTH_PATH": "custom-approle",
			},
			verify: func(t *testing.T, a authenticator) { assertAppRole(t, a, "env-role", "env-secret", "custom-approle") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			auth, err := newAuthenticator(VaultOpts{})
			if err != nil {
				t.Fatalf("newAuthenticator() unexpected error: %v", err)
			}
			tt.verify(t, auth)
		})
	}
}

// TestNewAuthenticatorEnvTransportOnly proves that transport-only options
// (Address, TransitSecretEnginePath) do not switch off the env auth source:
// with Auth == nil, credentials still come from the environment.
func TestNewAuthenticatorEnvTransportOnly(t *testing.T) {
	transportOpts := []struct {
		name string
		opts VaultOpts
	}{
		{"address only", VaultOpts{Address: "https://vault.example.com"}},
		{"transit path only", VaultOpts{TransitSecretEnginePath: "custom-transit"}},
		{"address and transit path", VaultOpts{Address: "https://vault.example.com", TransitSecretEnginePath: "custom-transit"}},
	}

	for _, tt := range transportOpts {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			t.Setenv("VAULT_ROLE_ID", "env-role")
			t.Setenv("VAULT_SECRET_ID", "env-secret")

			auth, err := newAuthenticator(tt.opts)
			if err != nil {
				t.Fatalf("newAuthenticator() unexpected error: %v", err)
			}
			assertAppRole(t, auth, "env-role", "env-secret", "ar")
		})
	}
}

// TestNewAuthenticatorOpts covers the programmatic auth source: the auth method
// is selected explicitly via VaultOpts.Auth and env credentials are ignored.
func TestNewAuthenticatorOpts(t *testing.T) {
	tests := []struct {
		name   string
		opts   VaultOpts
		env    map[string]string
		verify func(*testing.T, authenticator)
	}{
		{
			name: "approle from opts ignores env credentials",
			opts: VaultOpts{Auth: &VaultAuth{AppRole: &AppRoleAuth{RoleID: "opts-role", SecretID: "opts-secret"}}},
			env:  map[string]string{"VAULT_ROLE_ID": "env-role", "VAULT_SECRET_ID": "env-secret"},
			verify: func(t *testing.T, a authenticator) {
				assertAppRole(t, a, "opts-role", "opts-secret", "ar")
			},
		},
		{
			name: "oidc from opts audience",
			opts: VaultOpts{Auth: &VaultAuth{OIDC: &OIDCAuth{Audience: "opts-audience", Role: "opts-role"}}},
			env: map[string]string{
				"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://example.com/token",
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
			},
			verify: func(t *testing.T, a authenticator) { assertOIDC(t, a, "opts-role", "jwt") },
		},
		{
			name:   "static jwt from opts",
			opts:   VaultOpts{Auth: &VaultAuth{JWT: &JWTAuth{JWT: "opts-jwt", Role: "opts-role"}}},
			verify: func(t *testing.T, a authenticator) { assertStaticJWT(t, a, "opts-role", "jwt") },
		},
		{
			name:   "static token from opts",
			opts:   VaultOpts{Auth: &VaultAuth{Token: &TokenAuth{Token: "opts-token"}}},
			verify: func(t *testing.T, a authenticator) { assertStaticToken(t, a, "opts-token") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			auth, err := newAuthenticator(tt.opts)
			if err != nil {
				t.Fatalf("newAuthenticator() unexpected error: %v", err)
			}
			tt.verify(t, auth)
		})
	}
}

// TestNewAuthenticatorOptsIncomplete proves that incomplete auth options in
// opts-mode return an error and never fall back to VAULT_TOKEN / ~/.vault-token.
func TestNewAuthenticatorOptsIncomplete(t *testing.T) {
	tests := []struct {
		name string
		opts VaultOpts
	}{
		{"approle role id without secret id", VaultOpts{Auth: &VaultAuth{AppRole: &AppRoleAuth{RoleID: "opts-role"}}}},
		{"approle secret id without role id", VaultOpts{Auth: &VaultAuth{AppRole: &AppRoleAuth{SecretID: "opts-secret"}}}},
		{"oidc without audience", VaultOpts{Auth: &VaultAuth{OIDC: &OIDCAuth{Role: "opts-role"}}}},
		{"jwt without token", VaultOpts{Auth: &VaultAuth{JWT: &JWTAuth{Role: "opts-role"}}}},
		{"token without value", VaultOpts{Auth: &VaultAuth{Token: &TokenAuth{}}}},
		{"empty auth with no method", VaultOpts{Auth: &VaultAuth{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			// A host token that MUST NOT be picked up in opts-mode.
			t.Setenv("VAULT_TOKEN", "host-token-must-not-be-used")

			_, err := newAuthenticator(tt.opts)
			if err == nil {
				t.Fatal("expected error for incomplete opts, got nil")
			}
			if !strings.Contains(err.Error(), "incomplete Vault auth options") {
				t.Errorf("error = %q, want it to contain %q", err.Error(), "incomplete Vault auth options")
			}
		})
	}
}

// TestNewAuthenticatorOptsMultiple proves that setting more than one auth
// method in VaultOpts.Auth is an explicit configuration error, without any
// silent priority-based selection.
func TestNewAuthenticatorOptsMultiple(t *testing.T) {
	tests := []struct {
		name string
		auth *VaultAuth
	}{
		{"approle and token", &VaultAuth{AppRole: &AppRoleAuth{RoleID: "r", SecretID: "s"}, Token: &TokenAuth{Token: "t"}}},
		{"jwt and oidc", &VaultAuth{JWT: &JWTAuth{JWT: "j"}, OIDC: &OIDCAuth{Audience: "a"}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			t.Setenv("VAULT_TOKEN", "host-token-must-not-be-used")

			_, err := newAuthenticator(VaultOpts{Auth: tt.auth})
			if err == nil {
				t.Fatal("expected error for multiple auth methods, got nil")
			}
			if !strings.Contains(err.Error(), "multiple auth methods set") {
				t.Errorf("error = %q, want it to contain %q", err.Error(), "multiple auth methods set")
			}
		})
	}
}

// TestNewAuthenticatorOptsOIDCMissingActionsEnv proves that opts-mode OIDC
// errors when the GitHub Actions request variables are missing, and that the
// message does not reference the WERF_ACTIONS_AUDIENCE env variable since the
// audience came from code.
func TestNewAuthenticatorOptsOIDCMissingActionsEnv(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"missing request url", map[string]string{"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token"}},
		{"missing request token", map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "https://example.com/token"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearVaultEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			_, err := newAuthenticator(VaultOpts{Auth: &VaultAuth{OIDC: &OIDCAuth{Audience: "opts-audience"}}})
			if err == nil {
				t.Fatal("expected error for missing Actions OIDC env, got nil")
			}
			if !strings.Contains(err.Error(), "OIDC audience is configured") {
				t.Errorf("error = %q, want it to contain %q", err.Error(), "OIDC audience is configured")
			}
			if strings.Contains(err.Error(), "WERF_ACTIONS_AUDIENCE") {
				t.Errorf("error = %q, must not reference WERF_ACTIONS_AUDIENCE in opts-mode", err.Error())
			}
		})
	}
}

// TestNewAuthenticatorAuthPath verifies auth-path resolution for AppRole and
// JWT: VaultOpts auth Path takes precedence over WERF_VAULT_AUTH_PATH in
// env-mode, and the "ar"/"jwt" defaults apply when no path is set.
func TestNewAuthenticatorAuthPath(t *testing.T) {
	t.Run("opts auth path wins over env for approle", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv("WERF_VAULT_AUTH_PATH", "env-path")

		auth, err := newAuthenticator(VaultOpts{
			Auth: &VaultAuth{AppRole: &AppRoleAuth{
				RoleID:   "opts-role",
				SecretID: "opts-secret",
				Path:     "opts-path",
			}},
		})
		if err != nil {
			t.Fatalf("newAuthenticator() unexpected error: %v", err)
		}
		assertAppRole(t, auth, "opts-role", "opts-secret", "opts-path")
	})

	t.Run("env auth path applies to jwt when opts path absent", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv("WERF_VAULT_AUTH_JWT", "env-jwt")
		t.Setenv("WERF_VAULT_AUTH_PATH", "env-jwt-path")

		auth, err := newAuthenticator(VaultOpts{})
		if err != nil {
			t.Fatalf("newAuthenticator() unexpected error: %v", err)
		}
		assertStaticJWT(t, auth, "", "env-jwt-path")
	})

	t.Run("default ar path when unset for approle", func(t *testing.T) {
		clearVaultEnv(t)

		auth, err := newAuthenticator(VaultOpts{
			Auth: &VaultAuth{AppRole: &AppRoleAuth{
				RoleID:   "opts-role",
				SecretID: "opts-secret",
			}},
		})
		if err != nil {
			t.Fatalf("newAuthenticator() unexpected error: %v", err)
		}
		assertAppRole(t, auth, "opts-role", "opts-secret", "ar")
	})

	t.Run("default jwt path when unset for jwt", func(t *testing.T) {
		clearVaultEnv(t)

		auth, err := newAuthenticator(VaultOpts{Auth: &VaultAuth{JWT: &JWTAuth{JWT: "opts-jwt"}}})
		if err != nil {
			t.Fatalf("newAuthenticator() unexpected error: %v", err)
		}
		assertStaticJWT(t, auth, "", "jwt")
	})
}

// TestStaticAuthenticatorLoginInstallsToken verifies that a static token
// authenticator installs its configured token onto the Vault client on every
// login, overriding any VAULT_TOKEN the SDK auto-loaded at client construction.
// This guards the opts-mode guarantee that credentials come only from the
// selected variant and never from the host environment.
func TestStaticAuthenticatorLoginInstallsToken(t *testing.T) {
	t.Run("overrides conflicting VAULT_TOKEN", func(t *testing.T) {
		clearVaultEnv(t)
		t.Setenv("VAULT_TOKEN", "env-token")

		client, err := vault.NewClient(nil)
		if err != nil {
			t.Fatalf("vault.NewClient() unexpected error: %v", err)
		}
		if got := client.Token(); got != "env-token" {
			t.Fatalf("precondition: client token = %q, want %q", got, "env-token")
		}

		auth := newStaticAuthProvider("configured-token")
		if err := auth.Login(client); err != nil {
			t.Fatalf("Login() unexpected error: %v", err)
		}
		if got := client.Token(); got != "configured-token" {
			t.Errorf("client token = %q, want %q", got, "configured-token")
		}
	})

	t.Run("installs token when VAULT_TOKEN unset", func(t *testing.T) {
		clearVaultEnv(t)

		client, err := vault.NewClient(nil)
		if err != nil {
			t.Fatalf("vault.NewClient() unexpected error: %v", err)
		}
		if got := client.Token(); got != "" {
			t.Fatalf("precondition: client token = %q, want empty", got)
		}

		auth := newStaticAuthProvider("configured-token")
		if err := auth.Login(client); err != nil {
			t.Fatalf("Login() unexpected error: %v", err)
		}
		if got := client.Token(); got != "configured-token" {
			t.Errorf("client token = %q, want %q", got, "configured-token")
		}
	})
}
