package hashivault

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

type jwtAuthenticator struct {
	baseAuthenticator
	jwtProvider jwtTokenProvider
	role        string
}

func newJWTAuthenticator(provider jwtTokenProvider, role, authPath string) *jwtAuthenticator {
	if authPath == "" {
		authPath = "jwt"
	}

	return &jwtAuthenticator{
		baseAuthenticator: baseAuthenticator{
			authPath: authPath,
		},
		jwtProvider: provider,
		role:        role,
	}
}

func (j *jwtAuthenticator) Login(client *vault.Client) error {
	if j.isTokenValid() {
		client.SetToken(j.tokenID)
		return nil
	}

	jwtToken, err := j.jwtProvider.GetToken()
	if err != nil {
		return fmt.Errorf("failed to get JWT token: %w", err)
	}

	loginData := map[string]interface{}{
		"role": j.role,
		"jwt":  jwtToken,
	}
	return j.baseAuthenticator.login(client, loginData)
}
