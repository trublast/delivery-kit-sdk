package hashivault

import (
	"time"

	vault "github.com/hashicorp/vault/api"
)

type staticAuthenticator struct {
	baseAuthenticator
}

func newStaticAuthProvider(token string) *staticAuthenticator {
	return &staticAuthenticator{
		baseAuthenticator: baseAuthenticator{
			tokenID:       token,
			tokenTTL:      300 * time.Second,
			tokenIssuedAt: time.Now(),
		},
	}
}

func (s *staticAuthenticator) Login(client *vault.Client) error {
	client.SetToken(s.tokenID)
	return nil
}
