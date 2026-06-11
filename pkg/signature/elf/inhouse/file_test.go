//go:build linux
// +build linux

package inhouse_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/elf/inhouse"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
	"github.com/deckhouse/delivery-kit-sdk/test/pkg/cert_utils"
)

const (
	helloTxtFile                      = "../../../../test/data/hello.txt"
	helloElfFile                      = "../../../../test/data/hello.elf"
	helloElfFileWithSignature         = "../../../../test/data/hello_with_signature.elf"
	helloElfFileWithOutdatedSignature = "../../../../test/data/hello_with_outdated_signature.elf"
	helloSectionlessElfFile           = "../../../../test/data/hello_sectionless.elf"
)

var _ = Describe("signature/elf/custom", func() {
	DescribeTable("should add new signature",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloElfFile)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloElfFile, "hello.*.elf")
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			newElfBinary := readFile(newElfFilePath)
			fixtureNewElfBinary := readFile(helloElfFileWithSignature)

			Expect(newElfBinary).NotTo(Equal(oldElfBinary))
			Expect(newElfBinary).To(Equal(fixtureNewElfBinary))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should update outdated signature",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloElfFileWithOutdatedSignature)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloElfFileWithOutdatedSignature, "hello.*.elf")
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(Succeed())

			newElfBinary := readFile(newElfFilePath)
			fixtureNewElfBinary := readFile(helloElfFileWithSignature)

			Expect(newElfBinary).NotTo(Equal(oldElfBinary))
			Expect(newElfBinary).To(Equal(fixtureNewElfBinary))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to sign non-elf file",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldTxtData := readFile(helloTxtFile)
			newTxtFilePath, cleanupTmpFile := makeTempFileCopy(helloTxtFile, "hello.*.txt")
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newTxtFilePath)).To(Equal(elf.ErrNotELF))

			newTxtData := readFile(newTxtFilePath)
			Expect(newTxtData).To(Equal(oldTxtData))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should verify signature",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFileWithSignature)).To(Succeed())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify signature because wrong signature",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFileWithOutdatedSignature)).To(HaveOccurred())
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify signature because no signature",
		func(ctx SpecContext, errMatcher types.GomegaMatcher) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloElfFile)).To(errMatcher)
		},
		Entry(
			"with x509 certs",
			MatchError(elf.ErrNoSignatureSection),
		),
	)

	DescribeTable("should fail to sign sectionless elf",
		func(ctx SpecContext) {
			signerVerifier := newSignerVerifier(ctx)

			oldElfBinary := readFile(helloSectionlessElfFile)
			newElfFilePath, cleanupTmpFile := makeTempFileCopy(helloSectionlessElfFile, "hello_sectionless.*.elf")
			defer cleanupTmpFile()

			Expect(inhouse.Sign(ctx, signerVerifier, newElfFilePath)).To(MatchError(elf.ErrNoSections))

			newElfBinary := readFile(newElfFilePath)
			Expect(newElfBinary).To(Equal(oldElfBinary))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify sectionless elf",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloSectionlessElfFile)).To(MatchError(elf.ErrNoSections))
		},
		Entry(
			"with x509 certs",
		),
	)

	DescribeTable("should fail to verify non-elf file",
		func(ctx SpecContext) {
			Expect(inhouse.Verify(ctx, []string{cert_utils.RootCABase64}, helloTxtFile)).To(Equal(elf.ErrNotELF))
		},
		Entry(
			"with x509 certs",
		),
	)
})

func newSignerVerifier(ctx SpecContext) *signver.SignerVerifier {
	signerVerifier, err := signver.NewSignerVerifier(ctx, cert_utils.SignerCertBase64, cert_utils.SignerChainBase64, signver.KeyOpts{
		KeyRef: cert_utils.SignerKeyBase64,
	})
	Expect(err).To(Succeed())

	return signerVerifier
}

func readFile(path string) []byte {
	data, err := os.ReadFile(path)
	Expect(err).To(Succeed())

	return data
}

func makeTempFileCopy(srcPath, tmpPattern string) (tmpFilePath string, tmpFileCleanupFn func()) {
	srcData := readFile(srcPath)

	tmpFile, err := os.CreateTemp("", tmpPattern)
	Expect(err).To(Succeed())

	_, err = tmpFile.Write(srcData)
	Expect(err).To(Succeed())

	tmpFilePath = tmpFile.Name()
	Expect(tmpFile.Close()).To(Succeed())

	tmpFileCleanupFn = func() { os.Remove(tmpFilePath) }

	return tmpFilePath, tmpFileCleanupFn
}
