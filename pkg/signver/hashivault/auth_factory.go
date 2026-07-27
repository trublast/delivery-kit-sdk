package hashivault

import (
	"fmt"
)

func newAuthenticator(opts VaultOpts) (authenticator, error) {
	if opts.Auth == nil {
		return newAuthenticatorFromEnv()
	}
	return newAuthenticatorFromOpts(opts.Auth)
}

func newAuthenticatorFromEnv() (authenticator, error) {
	roleID := getVaultAuthRoleId()
	secretID := getVaultAuthSecretId()
	authPath := getVaultAuthPath()
	audience := getActionsAudience()
	authRole := getVaultAuthRole()
	jwtToken := getVaultAuthJwt()

	if roleID != "" && secretID != "" {
		return newAppRoleAuthenticator(roleID, secretID, authPath), nil
	} else if audience != "" {
		requestURL := getActionsIDTokenRequestURL()
		requestToken := getActionsIDTokenRequestToken()
		if requestURL == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_URL is missing")
		}
		if requestToken == "" {
			return nil, fmt.Errorf("WERF_ACTIONS_AUDIENCE is set but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing")
		}
		provider := newActionsOidcJwtTokenProvider(requestURL, requestToken, audience)
		return newJWTAuthenticator(provider, authRole, authPath), nil
	} else if jwtToken != "" {
		provider := newStaticJwtTokenProvider(jwtToken)
		return newJWTAuthenticator(provider, authRole, authPath), nil
	}

	token, err := getVaultToken("")
	if err != nil {
		return nil, err
	}
	return newStaticAuthProvider(token), nil
}

func newAuthenticatorFromOpts(auth *VaultAuth) (authenticator, error) {
	if err := auth.validate(); err != nil {
		return nil, err
	}

	switch {
	case auth.AppRole != nil:
		ar := auth.AppRole
		if ar.RoleID == "" || ar.SecretID == "" {
			return nil, fmt.Errorf("incomplete Vault auth options: AppRole requires both RoleID and SecretID")
		}
		return newAppRoleAuthenticator(ar.RoleID, ar.SecretID, ar.Path), nil
	case auth.OIDC != nil:
		o := auth.OIDC
		if o.Audience == "" {
			return nil, fmt.Errorf("incomplete Vault auth options: OIDC requires Audience")
		}
		requestURL := getActionsIDTokenRequestURL()
		requestToken := getActionsIDTokenRequestToken()
		if requestURL == "" {
			return nil, fmt.Errorf("OIDC audience is configured but ACTIONS_ID_TOKEN_REQUEST_URL is missing")
		}
		if requestToken == "" {
			return nil, fmt.Errorf("OIDC audience is configured but ACTIONS_ID_TOKEN_REQUEST_TOKEN is missing")
		}
		provider := newActionsOidcJwtTokenProvider(requestURL, requestToken, o.Audience)
		return newJWTAuthenticator(provider, o.Role, o.Path), nil
	case auth.JWT != nil:
		j := auth.JWT
		if j.JWT == "" {
			return nil, fmt.Errorf("incomplete Vault auth options: JWT requires JWT")
		}
		provider := newStaticJwtTokenProvider(j.JWT)
		return newJWTAuthenticator(provider, j.Role, j.Path), nil
	case auth.Token != nil:
		if auth.Token.Token == "" {
			return nil, fmt.Errorf("incomplete Vault auth options: Token requires Token")
		}
		return newStaticAuthProvider(auth.Token.Token), nil
	default:
		return nil, fmt.Errorf("incomplete Vault auth options: set exactly one of AppRole/OIDC/JWT/Token")
	}
}

// validate ensures exactly one auth method variant is set.
func (a *VaultAuth) validate() error {
	n := 0
	if a.AppRole != nil {
		n++
	}
	if a.OIDC != nil {
		n++
	}
	if a.JWT != nil {
		n++
	}
	if a.Token != nil {
		n++
	}
	if n == 0 {
		return fmt.Errorf("incomplete Vault auth options: set exactly one of AppRole/OIDC/JWT/Token")
	}
	if n > 1 {
		return fmt.Errorf("ambiguous Vault auth options: multiple auth methods set, set exactly one of AppRole/OIDC/JWT/Token")
	}
	return nil
}
