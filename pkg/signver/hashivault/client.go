//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hashivault implement the interface with hashivault kms service
package hashivault

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	vault "github.com/hashicorp/vault/api"
	"github.com/jellydator/ttlcache/v3"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type hashivaultClient struct {
	client                  *vault.Client
	keyPath                 string
	transitSecretEnginePath string
	keyCache                *ttlcache.Cache[string, crypto.PublicKey]
	keyVersion              uint64
	auth                    authenticator
	// For the ED25519 algorithm, the standard (RFC 8032) implies signing a message
	// without external hashing (disable prehashing in Vault terms).
	originalHashFunc crypto.Hash
}

// VaultOpts configures the Vault SignerVerifier programmatically.
//
// Transport options (Address, TransitSecretEnginePath) are always resolved
// independently, falling back to environment variables and defaults when empty.
//
// Auth selects the authentication method: when nil, credentials are read from
// the environment (env-mode); when set, credentials are taken ONLY from Auth
// and the environment is never consulted for credentials (except the GitHub
// Actions OIDC request URL/token, which are always injected by the runner).
type VaultOpts struct {
	// Address is the Vault server address (env: VAULT_ADDR).
	Address string
	// TransitSecretEnginePath is the transit engine mount path
	// (env: TRANSIT_SECRET_ENGINE_PATH, default "transit").
	TransitSecretEnginePath string
	// Auth selects the programmatic auth method. When nil, auth is resolved
	// from the environment.
	Auth *VaultAuth
}

// VaultAuth selects exactly one authentication method. Exactly one field must
// be non-nil; setting zero or more than one is a configuration error.
type VaultAuth struct {
	// AppRole authenticates via Vault AppRole.
	AppRole *AppRoleAuth
	// OIDC authenticates via GitHub Actions OIDC.
	OIDC *OIDCAuth
	// JWT authenticates via a static JWT.
	JWT *JWTAuth
	// Token authenticates via a static Vault token.
	Token *TokenAuth
}

// AppRoleAuth authenticates via Vault AppRole. RoleID and SecretID are both
// required.
type AppRoleAuth struct {
	// RoleID is the AppRole role id.
	RoleID string
	// SecretID is the AppRole secret id.
	SecretID string
	// Path is the AppRole auth mount path. Defaults to "ar" when empty.
	Path string
}

// OIDCAuth authenticates via GitHub Actions OIDC. Audience is required; the
// request URL and token are always read from the ACTIONS_ID_TOKEN_REQUEST_URL
// and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables injected by GitHub
// Actions.
type OIDCAuth struct {
	// Audience is the OIDC token audience.
	Audience string
	// Role is the Vault JWT/OIDC role.
	Role string
	// Path is the JWT auth mount path. Defaults to "jwt" when empty.
	Path string
}

// JWTAuth authenticates via a static JWT.
type JWTAuth struct {
	// JWT is the raw JWT to authenticate with.
	JWT string
	// Role is the Vault JWT role.
	Role string
	// Path is the JWT auth mount path. Defaults to "jwt" when empty.
	Path string
}

// TokenAuth authenticates via a static Vault token.
type TokenAuth struct {
	// Token is the Vault token.
	Token string
}

const (
	// use a consistent key for cache lookups
	cacheKey = "signer"
)

func newHashivaultClient(auth authenticator, address, transitSecretEnginePath, keyResourceID string, keyVersion uint64, originalHashFunc crypto.Hash) (*hashivaultClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}

	keyPath, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	if address, err = getVaultAddress(address); err != nil {
		return nil, err
	}

	client, err := vault.NewClient(&vault.Config{
		Address: address,
	})
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	// vault.NewClient auto-loads VAULT_TOKEN from the environment. Clear it so a
	// host token never leaks in the X-Vault-Token header of AppRole/JWT/OIDC
	// login requests; each authenticator installs its own token via SetToken
	// before performing signing operations.
	client.ClearToken()

	hvClient := &hashivaultClient{
		client:                  client,
		keyPath:                 keyPath,
		transitSecretEnginePath: getVaultTransitSecretEnginePath(transitSecretEnginePath),
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
		keyVersion: keyVersion,
		auth:       auth,
		// Vault ACL path compatibility with "cosign attest" requires original hash function
		originalHashFunc: originalHashFunc,
	}

	return hvClient, nil
}

func (h *hashivaultClient) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
	client := h.client.Logical()

	path := fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath)

	if err := h.auth.Login(h.client); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	keyResult, err := client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	if keyResult == nil {
		return nil, fmt.Errorf("could not read data from transit key path: %s", path)
	}

	keysData, hasKeys := keyResult.Data["keys"]
	latestVersion, hasVersion := keyResult.Data["latest_version"]
	if !hasKeys || !hasVersion {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keys, ok := keysData.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to read transit key keys: Invalid keys map")
	}

	keyVersion, ok := latestVersion.(json.Number)
	if !ok {
		return nil, fmt.Errorf("format of 'latest_version' is not json.Number")
	}

	keyData, ok := keys[string(keyVersion)]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keyMap, ok := keyData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("could not parse transit key keys data as map[string]interface{}")
	}

	publicKeyPem, ok := keyMap["public_key"]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	strPublicKeyPem, ok := publicKeyPem.(string)
	if !ok {
		return nil, fmt.Errorf("could not parse public key pem as string")
	}

	// Vault Transit Engine returns ed25519 public keys as a raw base64-encoded string
	// of the 32-byte key, unlike RSA or ECDSA which are returned as PEM blocks.
	if keyType := keyMap["name"]; keyType == "ed25519" {
		decodedPublicKey, err := base64.StdEncoding.DecodeString(strPublicKeyPem)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode ed25519 public key: %w", err)
		}
		if keyLen := len(decodedPublicKey); keyLen != ed25519.PublicKeySize {
			return nil, fmt.Errorf("decoded ed25519 public key length is %d, should be %d", keyLen, ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(decodedPublicKey), nil
	}

	return cryptoutils.UnmarshalPEMToPublicKey([]byte(strPublicKeyPem))
}

func (h *hashivaultClient) public() (crypto.PublicKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, lerr = h.fetchPublicKey(context.Background())
			if lerr == nil {
				item := c.Set(key, pubkey, h.auth.TokenTTL())
				return item
			}
			return nil
		},
	)

	item := h.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	if lerr != nil {
		return nil, lerr
	}

	if item == nil {
		return nil, fmt.Errorf("unable to retrieve an item from the cache by the provided key")
	}

	return item.Value(), nil
}

func (h *hashivaultClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	client := h.client.Logical()

	keyVersion := fmt.Sprintf("%d", h.keyVersion)
	var keyVersionUsedPtr *string
	for _, opt := range opts {
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyKeyVersionUsed(&keyVersionUsedPtr)
	}

	if keyVersion != "" {
		if _, err := strconv.ParseUint(keyVersion, 10, 64); err != nil {
			return nil, fmt.Errorf("parsing requested key version: %w", err)
		}
	}

	if err := h.auth.Login(h.client); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	signResult, err := client.Write(fmt.Sprintf("/%s/sign/%s%s", h.transitSecretEnginePath, h.keyPath, hashString(h.originalHashFunc)), map[string]interface{}{
		"input": base64.StdEncoding.Strict().EncodeToString(digest),
		// ED25519 requires to disable pre-hashing, Vault Transit signs the raw message.
		"prehashed":           !isEd25519Hash(alg),
		"key_version":         keyVersion,
		"signature_algorithm": "pkcs1v15",
	})
	if err != nil {
		return nil, fmt.Errorf("transit: failed to sign payload: %w", err)
	}

	encodedSignature, ok := signResult.Data["signature"]
	if !ok {
		return nil, errors.New("transit: response corrupted in-transit")
	}

	return vaultDecode(encodedSignature, keyVersionUsedPtr)
}

func (h *hashivaultClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {
	client := h.client.Logical()
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	keyVersion := ""
	for _, opt := range opts {
		opt.ApplyKeyVersion(&keyVersion)
	}

	vaultDataPrefix, err := determineVaultDataPrefix(keyVersion, h.keyVersion)
	if err != nil {
		return err
	}

	if err = h.auth.Login(h.client); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	result, err := client.Write(fmt.Sprintf("/%s/verify/%s/%s", h.transitSecretEnginePath, h.keyPath, hashString(h.originalHashFunc)), map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(digest),
		// ED25519 requires to disable pre-hashing, Vault Transit signs the raw message.
		"prehashed": !isEd25519Hash(alg),
		"signature": fmt.Sprintf("%s%s", vaultDataPrefix, encodedSig),
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	valid, ok := result.Data["valid"]
	if !ok {
		return errors.New("corrupted response")
	}

	isValid, ok := valid.(bool)
	if !ok {
		return fmt.Errorf("received non-bool value from 'valid' key")
	}

	if !isValid {
		return errors.New("failed vault verification")
	}

	return nil
}

func (h *hashivaultClient) createKey(typeStr string) (crypto.PublicKey, error) {
	client := h.client.Logical()

	if err := h.auth.Login(h.client); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	if _, err := client.Write(fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath), map[string]interface{}{
		"type": typeStr,
	}); err != nil {
		return nil, fmt.Errorf("failed to create transit key: %w", err)
	}
	return h.public()
}
