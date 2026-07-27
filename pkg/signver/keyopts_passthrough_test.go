package signver_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault"
)

var _ = Describe("KeyOpts SignerVerifierOpts passthrough", func() {
	It("routes hashivault key refs through the Vault loader with the provided VaultOpts", func(ctx SpecContext) {
		// Incomplete auth options force opts-mode, which fails deterministically
		// with a specific error before any Vault client or network call. Reaching
		// that error proves KeyOpts.SignerVerifierOpts.VaultOpts is threaded down
		// to the Vault authenticator factory.
		_, err := signver.NewSignerVerifier(ctx, "", "", signver.KeyOpts{
			KeyRef: hashivault.ReferenceScheme + "some-key",
			SignerVerifierOpts: signver.SignerVerifierOpts{
				VaultOpts: hashivault.VaultOpts{
					Auth: &hashivault.VaultAuth{
						AppRole: &hashivault.AppRoleAuth{RoleID: "role-without-secret"},
					},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("incomplete Vault auth options"))
	})

	It("does not route non-Vault key refs through the Vault loader", func(ctx SpecContext) {
		_, err := signver.NewSignerVerifier(ctx, "", "", signver.KeyOpts{
			KeyRef: "pkcs11:some-token",
			SignerVerifierOpts: signver.SignerVerifierOpts{
				VaultOpts: hashivault.VaultOpts{
					Auth: &hashivault.VaultAuth{
						AppRole: &hashivault.AppRoleAuth{RoleID: "role-without-secret"},
					},
				},
			},
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("incomplete Vault auth options"))
		Expect(err.Error()).To(ContainSubstring("pkcs11"))
	})

	It("rejects an empty key ref before touching any loader", func() {
		_, err := signver.NewSignerVerifier(context.Background(), "", "", signver.KeyOpts{})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("KeyRef must not be empty"))
	})
})
