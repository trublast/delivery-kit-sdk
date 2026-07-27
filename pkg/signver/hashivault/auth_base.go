package hashivault

import (
	"fmt"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// baseAuthenticator provides shared authentication logic for Vault.
// The fields tokenID, tokenTTL, and tokenIssuedAt are protected by mu
// since Login() can be called concurrently from multiple goroutines.
type baseAuthenticator struct {
	mu            sync.Mutex
	authPath      string
	tokenID       string
	tokenTTL      time.Duration
	tokenIssuedAt time.Time
}

func (b *baseAuthenticator) login(client *vault.Client, data map[string]interface{}) error {
	resp, err := client.Logical().Write(fmt.Sprintf("/auth/%s/login", b.authPath), data)
	if err != nil {
		return fmt.Errorf("vault write: %w", err)
	}

	tokenID, err := resp.TokenID()
	if err != nil {
		return fmt.Errorf("getting auth token id: %w", err)
	}
	tokenTTL, err := resp.TokenTTL()
	if err != nil {
		return fmt.Errorf("getting auth token TTL: %w", err)
	}

	// Protect writes to token fields from concurrent access
	b.mu.Lock()
	b.tokenID = tokenID
	b.tokenTTL = tokenTTL
	b.tokenIssuedAt = time.Now()
	b.mu.Unlock()

	client.SetToken(b.tokenID)

	return nil
}

// isTokenValid checks if the cached Vault token is still valid.
// A safety margin of 30 seconds is used to avoid edge cases with token expiration.
func (b *baseAuthenticator) isTokenValid() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tokenID == "" {
		return false
	}
	if b.tokenTTL <= 0 {
		return false
	}
	elapsed := time.Since(b.tokenIssuedAt)
	// Re-authenticate if less than 30 seconds remain before expiration
	return elapsed < b.tokenTTL-30*time.Second
}

func (b *baseAuthenticator) Login(client *vault.Client) error {
	panic("not implemented")
}

func (b *baseAuthenticator) TokenTTL() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.tokenTTL
}
