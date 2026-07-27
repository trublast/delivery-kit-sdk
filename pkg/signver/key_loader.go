package signver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/crypto/ed25519"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/blob"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver/hashivault"
)

const (
	pkcs11KeyReferenceScheme     = "pkcs11:"
	kubernetesKeyReferenceSchema = "k8s://"
	gitLabReferenceScheme        = "gitlab://"
)

// signerVerifierFromKeyRef
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/signature/keys.go#L103
// and modified after.
func signerVerifierFromKeyRef(ctx context.Context, keyRef string, passFunc cryptoutils.PassFunc, opts SignerVerifierOpts) (signature.SignerVerifier, error) {
	if keyRef == "" {
		return nil, errors.New("keyRef must not be empty string")
	}

	switch {
	case strings.HasPrefix(keyRef, pkcs11KeyReferenceScheme):
		return nil, errors.New("pkcs11 keys are not supported")
	case strings.HasPrefix(keyRef, kubernetesKeyReferenceSchema):
		return nil, errors.New("kubernetes keys are not supported")
	case strings.HasPrefix(keyRef, gitLabReferenceScheme):
		return nil, errors.New("gitlab keys are not supported")
	case strings.HasPrefix(keyRef, hashivault.ReferenceScheme):
		return hashivault.LoadSignerVerifierWithOpts(keyRef, crypto.SHA256, opts.VaultOpts)
	default:
		sv, err := loadKey(keyRef, passFunc)
		if err != nil {
			return nil, fmt.Errorf("reading key: %w", err)
		}
		return sv, nil
	}
}

// loadKey
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/signature/keys.go#L75
// and modified after.
func loadKey(keyPath string, pf cryptoutils.PassFunc) (signature.SignerVerifier, error) {
	kb, err := blob.LoadURLOrBase64OrFile(keyPath)
	if err != nil {
		return nil, err
	}
	pass := []byte{}
	if pf != nil {
		pass, err = pf(false)
		if err != nil {
			return nil, err
		}
	}
	return loadPrivateKey(kb, pass)
}

// loadPrivateKey loads a PEM private key encrypted with the given passphrase,
// and returns a SignerVerifier instance. The private key must be in the PKCS #8 format.
// Copied from https://github.com/sigstore/cosign/blob/c948138c19691142c1e506e712b7c1646e8ceb21/pkg/cosign/keys.go#L212
// and modified after.
func loadPrivateKey(key, pass []byte) (signature.SignerVerifier, error) {
	// Decrypt first
	p, _ := pem.Decode(key)
	if p == nil {
		return nil, errors.New("invalid pem block")
	}

	if p.Type != DeliveryKitPrivateKeyPemType && p.Type != PrivateKeyPemType {
		return nil, fmt.Errorf("unsupported pem type: %s", p.Type)
	}

	x509Encoded, err := encrypted.Decrypt(p.Bytes, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	pk, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	switch pk := pk.(type) {
	case *rsa.PrivateKey:
		return signature.LoadRSAPKCS1v15SignerVerifier(pk, crypto.SHA256)
	case *ecdsa.PrivateKey:
		return signature.LoadECDSASignerVerifier(pk, crypto.SHA256)
	case ed25519.PrivateKey:
		return signature.LoadED25519SignerVerifier(pk)
	default:
		return nil, errors.New("unsupported key type")
	}
}
