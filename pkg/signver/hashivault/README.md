# Vault Key Loader

This package implements loading keys from Vault server.

## General configuration

| Environment Variable       | Description                                                                                                    |
|----------------------------|----------------------------------------------------------------------------------------------------------------|
| VAULT_ADDR                 | [Address of Vault server](https://developer.hashicorp.com/vault/docs/commands#configure-environment-variables) | 
| TRANSIT_SECRET_ENGINE_PATH | [Path of transit engine](https://developer.hashicorp.com/vault/api-docs/secret/transit) (default `/transit`)   |

## Authentication methods

Before requesting server with "sing" / "verify" operations
you need to get an **access token** via one of next authentication methods.

| Name                       | Description                          | Environment Variables                                                                                                                                                             | URI (default)     | Renewal token | Refreshing token                                                    |
|----------------------------|--------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|---------------|---------------------------------------------------------------------|
| Static Token               | Explicitly sets access token         | `VAULT_TOKEN`                                                                                                                                                                     | Not used          | Not used      | Not used                                                            |
| App Role                   | Sets credentials to get access token | `WERF_VAULT_AUTH_ROLE_ID`, `WERF_VAULT_AUTH_SECRET_ID`                                                                                                                            | `/auth/ar/login`  | Not used      | Cached until Vault token expiry                                     |
| JSON Web Token (JWT)       | Sets credentials to get access token | `WERF_VAULT_AUTH_JWT`, `WERF_VAULT_AUTH_ROLE`                                                                                                                                     | `/auth/jwt/login` | Not used      | Cached until Vault token expiry                                     |
| GitHub Actions OIDC (JWT)  | Obtains a fresh JWT from GitHub OIDC endpoint on each login | `WERF_ACTIONS_AUDIENCE`, `WERF_VAULT_AUTH_ROLE`<br/>(uses GitHub-provided `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`) | `/auth/jwt/login` | Not used      | Fresh JWT from OIDC endpoint, cached until Vault token expiry      |

If auth method use default URI it could be configured with `WERF_VAULT_AUTH_PATH` environment variable. 

For example, JWT auth method uses `/auth/jwt/login` by default. 
So setting `WERF_VAULT_AUTH_PATH=github` we change the URI to `/auth/github/login`.

### Additional environment variables for GitHub Actions OIDC

When `WERF_ACTIONS_AUDIENCE` is set, the client requests a **fresh** OIDC token from the GitHub Actions OIDC endpoint
(`ACTIONS_ID_TOKEN_REQUEST_URL`) on each Vault login, using `ACTIONS_ID_TOKEN_REQUEST_TOKEN` for authorization.
This solves the 10-minute token expiry issue in GitHub Actions by obtaining a new, valid JWT before every login.

| Environment Variable            | Description                                                              | Required                        |
|---------------------------------|--------------------------------------------------------------------------|---------------------------------|
| `WERF_ACTIONS_AUDIENCE`        | Audience for the GitHub OIDC token request. **Activates** the OIDC flow. | Yes (triggers the flow)         |
| `ACTIONS_ID_TOKEN_REQUEST_URL` | GitHub OIDC endpoint URL (predefined by GitHub Actions).                 | Yes (error if missing)          |
| `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | Bearer token for OIDC endpoint (predefined by GitHub Actions).         | Yes (error if missing)          |

> **Note:** `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are automatically
> available in GitHub Actions jobs with `id-token: write` permission.
> See [GitHub OIDC documentation](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#oidc-token-permissions).

## Programmatic configuration (`VaultOpts`)

Besides environment variables, the loader can be configured in code through
`KeyOpts.SignerVerifierOpts.VaultOpts` passed to `signver.NewSignerVerifier`.
`VaultOpts` is defined in this package.

#### Top-level fields

| Field                     | Env equivalent               | Kind      |
|---------------------------|------------------------------|-----------|
| `Address`                 | `VAULT_ADDR`                 | Transport |
| `TransitSecretEnginePath` | `TRANSIT_SECRET_ENGINE_PATH` | Transport |
| `Auth`                    | —                            | Auth      |

`Auth` is a `*VaultAuth` that selects **exactly one** authentication method by
setting exactly one of its variant fields. Setting zero or more than one is a
configuration error.

| `VaultAuth` field | Type           | Method              |
|-------------------|----------------|---------------------|
| `AppRole`         | `*AppRoleAuth` | Vault AppRole       |
| `OIDC`            | `*OIDCAuth`    | GitHub Actions OIDC |
| `JWT`             | `*JWTAuth`     | Static JWT          |
| `Token`           | `*TokenAuth`   | Static Vault token  |

Per-method fields:

| Variant        | Fields                                | Env equivalent                                                                                  |
|----------------|---------------------------------------|-------------------------------------------------------------------------------------------------|
| `AppRoleAuth`  | `RoleID`, `SecretID`, `Path`          | `WERF_VAULT_AUTH_ROLE_ID` (or `VAULT_ROLE_ID`), `WERF_VAULT_AUTH_SECRET_ID` (or `VAULT_SECRET_ID`), `WERF_VAULT_AUTH_PATH` |
| `OIDCAuth`     | `Audience`, `Role`, `Path`            | `WERF_ACTIONS_AUDIENCE`, `WERF_VAULT_AUTH_ROLE`, `WERF_VAULT_AUTH_PATH`                          |
| `JWTAuth`      | `JWT`, `Role`, `Path`                 | `WERF_VAULT_AUTH_JWT`, `WERF_VAULT_AUTH_ROLE`, `WERF_VAULT_AUTH_PATH`                            |
| `TokenAuth`    | `Token`                               | `VAULT_TOKEN`                                                                                    |

`Path` defaults to `ar` for AppRole and `jwt` for JWT/OIDC when left empty.

### Transport vs. auth options

Transport options (`Address`, `TransitSecretEnginePath`) are always resolved
independently, falling back to their environment variables and defaults when
left empty. They never affect how authentication credentials are sourced.

The **authentication source** is selected by `Auth`:

- `Auth == nil` — env-mode: credentials are read from the environment,
  identical to the env-only behavior above (including the priority AppRole >
  GitHub Actions OIDC > static JWT > static token and the `VAULT_TOKEN` /
  `~/.vault-token` fallback).
- `Auth != nil` — opts-mode: credentials are taken **only** from the selected
  variant; environment auth variables are ignored. There is no priority chain —
  exactly one method must be set explicitly.

This lets you, for example, set `Address` in code while still authenticating
from CI environment variables (leave `Auth` nil).

### Example

```go
sv, err := signver.NewSignerVerifier(ctx, "", "", signver.KeyOpts{
	KeyRef: "hashivault://my-key",
	SignerVerifierOpts: signver.SignerVerifierOpts{
		VaultOpts: hashivault.VaultOpts{
			Address: "https://vault.example.com",
			Auth: &hashivault.VaultAuth{
				AppRole: &hashivault.AppRoleAuth{
					RoleID:   "role",
					SecretID: "secret",
					Path:     "approle",
				},
			},
		},
	},
})
```

> **Note:** in opts-mode, incomplete auth options (for example, `AppRole` with
> `RoleID` but no `SecretID`), no method set, or multiple methods set return an
> error. The loader does **not** silently fall back to `VAULT_TOKEN` or
> `~/.vault-token`, so it never signs under an unexpected host identity.
>
> GitHub Actions OIDC (`OIDCAuth`) still reads `ACTIONS_ID_TOKEN_REQUEST_URL`
> and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` from the environment, as those are
> injected by GitHub Actions.

### Authentication flow

All authenticators that obtain a Vault token via login (`jwtAuthenticator`, `appRoleAuthenticator`) cache the
Vault token and reuse it until it expires. A 30-second safety margin is used before expiration to avoid edge cases.

#### Optimal case — cached Vault token is still valid

```
sign() / verify() / public() → auth.Login()
  ├─ isTokenValid() = true → SetToken(cached_token_id) → return nil
  └─ Vault operation (sign / verify / read key)
```

No extra HTTP requests between Vault operations, only the operation itself.

#### Vault token expired

```
sign() / verify() / public() → auth.Login()
  ├─ isTokenValid() = false → obtain new credentials
  │   ├─ AppRole: role_id + secret_id (no additional calls)
  │   ├─ JWT (static): cached JWT from WERF_VAULT_AUTH_JWT (env-mode) or JWTAuth.JWT (opts-mode) (no additional calls)
  │   └─ JWT (GitHub Actions): GET ACTIONS_ID_TOKEN_REQUEST_URL → fresh JWT
  ├─ POST /auth/jwt/login (or /auth/ar/login) → new Vault token
  │  cached as token_id with TTL from response
  └─ Vault operation (sign / verify / read key)
```

When the Vault token expires, the client re-authenticates, obtains a fresh Vault token, and caches it.
For GitHub Actions, a fresh OIDC token is first requested from the GitHub OIDC endpoint,
ensuring it never expires regardless of the 10-minute GitHub OIDC token lifetime.
