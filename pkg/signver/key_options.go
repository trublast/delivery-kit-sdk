package signver

import (
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault"
)

// KeyOpts
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/options/key.go#L20
// and modified after.
type KeyOpts struct {
	// KeyRef could be a URL, a base64 or a file path
	KeyRef string
	// PassFunc
	PassFunc cryptoutils.PassFunc
	// SignerVerifierOpts
	SignerVerifierOpts SignerVerifierOpts
}

type SignerVerifierOpts struct {
	VaultOpts hashivault.VaultOpts
}
