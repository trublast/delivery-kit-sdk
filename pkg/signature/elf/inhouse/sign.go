package inhouse

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature"
	elfsig "github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

const maxSignatureEmbedAttempts = 3

// Sign embeds a delivery-kit signature into the provided ELF image.
// The input slice is replaced with the signed image and its backing array is reused when capacity permits.
func Sign(ctx context.Context, signerVerifier *signver.SignerVerifier, elfBytes *[]byte) error {
	f, err := parseELF(*elfBytes)
	if err != nil {
		return err
	}
	if !supportedMachine(f.ehdr.Machine) {
		return fmt.Errorf("unsupported ELF machine %d", f.ehdr.Machine)
	}

	for attempt := 0; attempt < maxSignatureEmbedAttempts; attempt++ {
		hash, err := computeELFHash(f)
		if err != nil {
			return fmt.Errorf("compute elf hash failed: %w", err)
		}

		bundle, err := signature.Sign(ctx, signerVerifier, hash)
		if err != nil {
			return fmt.Errorf("sign bundle: %w", err)
		}
		bundleBytes, err := json.Marshal(bundle)
		if err != nil {
			return fmt.Errorf("marshal signature bundle: %w", err)
		}

		signed, err := saveELFSignature(f, bundleBytes)
		if err != nil {
			return fmt.Errorf("saving ELF signature failed: %w", err)
		}
		*elfBytes = signed

		upd, err := parseELF(signed)
		if err != nil {
			return fmt.Errorf("parse signed ELF: %w", err)
		}
		updatedHash, err := computeELFHash(upd)
		if err != nil {
			return fmt.Errorf("compute updated elf hash failed: %w", err)
		}
		if updatedHash == hash {
			return nil
		}
		f = upd
	}

	return fmt.Errorf("ELF hash did not stabilize after %d signature embeds", maxSignatureEmbedAttempts)
}

// Verify checks the delivery-kit signature embedded in the provided ELF image.
func Verify(ctx context.Context, rootCertRefs []string, elfBytes []byte) error {
	f, err := parseELF(elfBytes)
	if err != nil {
		return err
	}

	hash, err := computeELFHash(f)
	if err != nil {
		return fmt.Errorf("compute elf hash failed: %w", err)
	}

	sig, err := getELFSignature(f)
	if err != nil {
		return fmt.Errorf("get elf signature failed: %w", err)
	}
	if len(sig) == 0 {
		return elfsig.ErrNoSignatureSection
	}

	var bundle *signature.Bundle
	if err := json.Unmarshal(sig, &bundle); err != nil {
		return fmt.Errorf("unmarshal signature bundle: %w", err)
	}

	if err := signature.VerifyBundle(ctx, *bundle, hash, rootCertRefs); err != nil {
		return fmt.Errorf("verify signature bundle: %w", err)
	}
	return nil
}
