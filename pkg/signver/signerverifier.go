package signver

import (
	"context"
	"errors"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	DeliveryKitPrivateKeyPemType = "ENCRYPTED DELIVERY-KIT PRIVATE KEY"
	// PEM-encoded PKCS #8 RSA, ECDSA or ED25519 private key
	PrivateKeyPemType = "PRIVATE KEY"
)

// SignerVerifier
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign.go#L585
// and modified after.
type SignerVerifier struct {
	Cert  []byte
	Chain []byte
	signature.SignerVerifier
}

// NewSignerVerifier
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/cmd/cosign/cli/sign/sign.go#L392
// and modified after.
//
// certRef could be a base64 or a file path
// certChainRef could be a base64 or a file path
func NewSignerVerifier(ctx context.Context, certRef, certChainRef string, ko KeyOpts) (*SignerVerifier, error) {
	if ko.KeyRef == "" {
		return nil, errors.New("ko.KeyRef must not be empty string")
	}

	k, err := signerVerifierFromKeyRef(ctx, ko.KeyRef, ko.PassFunc, ko.SignerVerifierOpts)
	if err != nil {
		return nil, fmt.Errorf("reading key: %w", err)
	}

	certSigner := &SignerVerifier{
		SignerVerifier: k,
	}

	// NOTE: PKCS11 keys are unsupported

	// Handle --cert flag
	if certRef != "" {
		pk, err := k.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("get public key: %w", err)
		}
		leafCert, err := VerifyCert(pk, certRef)
		if err != nil {
			return nil, fmt.Errorf("cert verification: %w", err)
		}
		pemBytes, err := cryptoutils.MarshalCertificateToPEM(leafCert)
		if err != nil {
			return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
		}
		if certSigner.Cert != nil {
			return nil, errors.New("overriding x509 certificate retrieved from the PKCS11 token")
		}
		certSigner.Cert = pemBytes
	}

	if certChainRef == "" {
		return certSigner, nil
	} else if certSigner.Cert == nil {
		return nil, errors.New("no leaf certificate found or provided while specifying chain")
	}

	// Handle --cert-chain flag
	if roots, intermediates, err := VerifyChain(certRef, certChainRef); err != nil {
		return nil, err
	} else {
		certChainPemBytes, err := cryptoutils.MarshalCertificatesToPEM(append(intermediates, roots...))
		if err != nil {
			return nil, fmt.Errorf("marshaling root intermediate certificate to PEM: %w", err)
		}
		certSigner.Chain = certChainPemBytes
	}

	return certSigner, nil
}
