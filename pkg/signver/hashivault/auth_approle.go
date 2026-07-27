package hashivault

import vault "github.com/hashicorp/vault/api"

type appRoleAuthenticator struct {
	baseAuthenticator
	roleID   string
	secretID string
}

func newAppRoleAuthenticator(roleID, secretID, authPath string) *appRoleAuthenticator {
	if authPath == "" {
		authPath = "ar"
	}

	return &appRoleAuthenticator{
		baseAuthenticator: baseAuthenticator{
			authPath: authPath,
		},
		roleID:   roleID,
		secretID: secretID,
	}
}

func (a *appRoleAuthenticator) Login(client *vault.Client) error {
	if a.isTokenValid() {
		client.SetToken(a.tokenID)
		return nil
	}

	loginData := map[string]interface{}{
		"role_id":   a.roleID,
		"secret_id": a.secretID,
	}
	return a.baseAuthenticator.login(client, loginData)
}
