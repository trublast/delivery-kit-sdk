package inhouse

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCreateParseELFNoteRoundTrip(t *testing.T) {
	payload := []byte(`{"io.deckhouse.delivery-kit.signature":"AQID"}`)
	note := createELFNote(binary.LittleEndian, signatureNoteName, payload, signatureNoteType)
	parsed, err := parseELFNote(binary.LittleEndian, note)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Name != signatureNoteName {
		t.Fatalf("name: got %q", parsed.Name)
	}
	if parsed.Type != signatureNoteType {
		t.Fatalf("type: got %#x", parsed.Type)
	}
	if string(parsed.Desc) != string(payload) {
		t.Fatalf("desc mismatch")
	}
}

func TestParseELFNoteRejectsShort(t *testing.T) {
	if _, err := parseELFNote(binary.LittleEndian, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error")
	}
}

func TestHashStableAcrossSignatureEmbed(t *testing.T) {
	raw := buildMinimalELF64(t)
	f, err := parseELF(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h1, err := computeELFHash(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	signed, err := saveELFSignature(f, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	f2, err := parseELF(signed)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if f2.findSection(signatureSectionName) < 0 {
		t.Fatal("signature section missing")
	}
	h2, err := computeELFHash(f2)
	if err != nil {
		t.Fatalf("hash signed: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash changed after embedding signature:\n before: %s\n after:  %s", h1, h2)
	}

	// Replace signature again; hash must still match.
	signed2, err := saveELFSignature(f2, []byte(`{"k":"v2"}`))
	if err != nil {
		t.Fatalf("save replace: %v", err)
	}
	f3, err := parseELF(signed2)
	if err != nil {
		t.Fatalf("parse replaced: %v", err)
	}
	h3, err := computeELFHash(f3)
	if err != nil {
		t.Fatalf("hash replaced: %v", err)
	}
	if h1 != h3 {
		t.Fatalf("hash changed after replacing signature")
	}
	sig, err := getELFSignature(f3)
	if err != nil {
		t.Fatalf("get sig: %v", err)
	}
	if string(sig) != `{"k":"v2"}` {
		t.Fatalf("unexpected signature payload: %s", sig)
	}
}

func TestHashMatchesWelfOnFixtures(t *testing.T) {
	// Digests produced by old-elf welf_compute_elf_hash / libelf elf_nextscn.
	const want = "769c028944246a3b0a9cb6e9a46ba1dbce1e88025f4c767a8daf77673e0fa4c5"
	root := "../../../../test/data"
	for _, name := range []string{"hello.elf", "hello_with_signature.elf"} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		f, err := parseELF(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		got, err := computeELFHash(f)
		if err != nil {
			t.Fatalf("hash %s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s hash mismatch:\n got:  %s\n want: %s", name, got, want)
		}
	}
}

func TestHashStableOnRealHelloELF(t *testing.T) {
	raw, err := os.ReadFile("../../../../test/data/hello.elf")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f, err := parseELF(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	h1, err := computeELFHash(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	signed, err := saveELFSignature(f, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	f2, err := parseELF(signed)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if f2.findSection(signatureSectionName) < 0 {
		t.Fatal("signature section missing")
	}
	// objcopy layout: .shstrtab last, signature immediately before .symtab/.strtab/.shstrtab.
	if f2.names[len(f2.names)-1] != shstrtabSectionName {
		t.Fatalf("last section: got %q, want %s", f2.names[len(f2.names)-1], shstrtabSectionName)
	}
	sigIdx := f2.findSection(signatureSectionName)
	symIdx := f2.findSection(symtabSectionName)
	if symIdx >= 0 && sigIdx != symIdx-1 {
		t.Fatalf("signature index %d, want immediately before .symtab at %d", sigIdx, symIdx)
	}
	if f2.ehdr.Shoff%8 != 0 {
		t.Fatalf("e_shoff %d not 8-byte aligned", f2.ehdr.Shoff)
	}
	// Existing section name offsets must be unchanged.
	for i := 1; i < len(f.shdrs); i++ {
		if f.names[i] == signatureSectionName || f.names[i] == shstrtabSectionName {
			continue
		}
		j := f2.findSection(f.names[i])
		if j < 0 {
			t.Fatalf("section %q missing after embed", f.names[i])
		}
		if f.shdrs[i].Name != f2.shdrs[j].Name {
			t.Fatalf("sh_name for %q changed: %d -> %d", f.names[i], f.shdrs[i].Name, f2.shdrs[j].Name)
		}
	}
	h2, err := computeELFHash(f2)
	if err != nil {
		t.Fatalf("hash signed: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash changed after embedding signature:\n before: %s\n after:  %s", h1, h2)
	}

	signed2, err := saveELFSignature(f2, []byte(`{"k":"v2"}`))
	if err != nil {
		t.Fatalf("save replace: %v", err)
	}
	f3, err := parseELF(signed2)
	if err != nil {
		t.Fatalf("parse replaced: %v", err)
	}
	h3, err := computeELFHash(f3)
	if err != nil {
		t.Fatalf("hash replaced: %v", err)
	}
	if h1 != h3 {
		t.Fatalf("hash changed after replacing signature")
	}
}

func TestWriterMatchesObjcopyFixture(t *testing.T) {
	root := "../../../../test/data"
	raw, err := os.ReadFile(filepath.Join(root, "hello.elf"))
	if err != nil {
		t.Fatalf("read source ELF: %v", err)
	}
	want, err := os.ReadFile("../../../../test/data/hello_with_signature.elf")
	if err != nil {
		t.Fatalf("read objcopy fixture: %v", err)
	}

	fixture, err := parseELF(want)
	if err != nil {
		t.Fatalf("parse objcopy fixture: %v", err)
	}
	payload, err := getELFSignature(fixture)
	if err != nil {
		t.Fatalf("get fixture signature: %v", err)
	}
	source, err := parseELF(raw)
	if err != nil {
		t.Fatalf("parse source ELF: %v", err)
	}
	got, err := saveELFSignature(source, payload)
	if err != nil {
		t.Fatalf("write signature: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("pure Go writer output differs from objcopy fixture")
	}
}

func TestObjcopyLayoutMatchesSamePayload(t *testing.T) {
	// Compare Go writer against a live objcopy embed of the same note bytes on /bin/bash
	// when available; otherwise skip.
	const bash = "/bin/bash"
	raw, err := os.ReadFile(bash)
	if err != nil {
		t.Skip(bash, err)
	}
	const objcopy = "/usr/bin/objcopy"
	if _, err := os.Stat(objcopy); err != nil {
		t.Skip("objcopy not available")
	}

	payload := []byte(`{"test":"objcopy-layout-match"}`)
	note := createELFNote(binary.LittleEndian, signatureNoteName, payload, signatureNoteType)

	dir := t.TempDir()
	notePath := filepath.Join(dir, "note")
	srcPath := filepath.Join(dir, "src.elf")
	dstPath := filepath.Join(dir, "dst.elf")
	if err := os.WriteFile(notePath, note, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcPath, raw, 0o755); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"--add-section", signatureSectionName + "=" + notePath,
		"--set-section-flags", signatureSectionName + "=n",
		srcPath, dstPath,
	}
	out, err := exec.Command(objcopy, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("objcopy: %v\n%s", err, out)
	}

	objcopySigned, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseELF(raw)
	if err != nil {
		t.Fatal(err)
	}
	goSigned, err := saveELFSignature(f, payload)
	if err != nil {
		t.Fatal(err)
	}

	if len(goSigned) != len(objcopySigned) {
		t.Fatalf("size: go=%d objcopy=%d", len(goSigned), len(objcopySigned))
	}
	// Compare section layout metadata; full bytes may still differ if objcopy
	// preserves orphan gaps we drop — check e_shoff/shnum/order/offsets.
	fg, err := parseELF(goSigned)
	if err != nil {
		t.Fatal(err)
	}
	fo, err := parseELF(objcopySigned)
	if err != nil {
		t.Fatal(err)
	}
	if fg.ehdr.Shnum != fo.ehdr.Shnum || fg.ehdr.Shstrndx != fo.ehdr.Shstrndx {
		t.Fatalf("hdr shnum/shstrndx: go=(%d,%d) objcopy=(%d,%d)",
			fg.ehdr.Shnum, fg.ehdr.Shstrndx, fo.ehdr.Shnum, fo.ehdr.Shstrndx)
	}
	if fg.ehdr.Shoff != fo.ehdr.Shoff {
		t.Fatalf("e_shoff: go=%d objcopy=%d", fg.ehdr.Shoff, fo.ehdr.Shoff)
	}
	for i := range fg.names {
		if fg.names[i] != fo.names[i] {
			t.Fatalf("section[%d] name: go=%q objcopy=%q", i, fg.names[i], fo.names[i])
		}
		if fg.shdrs[i].Offset != fo.shdrs[i].Offset || fg.shdrs[i].Size != fo.shdrs[i].Size {
			t.Fatalf("section[%d] %q off/size: go=(%#x,%#x) objcopy=(%#x,%#x)",
				i, fg.names[i],
				fg.shdrs[i].Offset, fg.shdrs[i].Size,
				fo.shdrs[i].Offset, fo.shdrs[i].Size)
		}
	}
	if !bytes.Equal(goSigned, objcopySigned) {
		// Report first differing offset for diagnosis.
		n := len(goSigned)
		for i := 0; i < n; i++ {
			if goSigned[i] != objcopySigned[i] {
				t.Fatalf("file bytes differ at %#x (go=%02x objcopy=%02x)", i, goSigned[i], objcopySigned[i])
			}
		}
	}
}

func TestSaveELFSignatureRejectsRelocatingSHFAlloc(t *testing.T) {
	raw := buildMinimalELF64(t)
	f, err := parseELF(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Append an SHF_ALLOC section after .shstrtab so insertAt points at .shstrtab
	// and the writer would relocate the ALLOC section without updating p_offset.
	allocData := []byte{0xde, 0xad}
	f.data = append(f.data, allocData...)
	f.shdrs = append(f.shdrs, elf64Shdr{
		Type:      1,
		Flags:     shfAlloc,
		Offset:    uint64(len(f.data) - len(allocData)),
		Size:      uint64(len(allocData)),
		Addralign: 1,
	})
	f.names = append(f.names, ".alloc_tail")
	f.ehdr.Shnum = uint16(len(f.shdrs))

	if _, err := saveELFSignature(f, []byte(`{"k":"v"}`)); err == nil {
		t.Fatal("expected error relocating SHF_ALLOC section")
	}
}

func TestParsePNXNUMReadsProgramHeaders(t *testing.T) {
	raw := buildMinimalELF64(t)
	bo := binary.LittleEndian
	// Mark e_phnum as PN_XNUM; real count goes into section 0 sh_info.
	bo.PutUint16(raw[56:58], pnXNum)
	shoff := bo.Uint64(raw[40:48])
	bo.PutUint32(raw[shoff+44:shoff+48], 1) // sh_info = 1 program header

	f, err := parseELF(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.phdrs) != 1 {
		t.Fatalf("phdrs: got %d, want 1", len(f.phdrs))
	}
	if f.phdrs[0].Filesz == 0 {
		t.Fatal("expected non-empty PT_LOAD filesz")
	}
}

func TestParseRejectsSectionless(t *testing.T) {
	raw := buildMinimalELF64(t)
	binary.LittleEndian.PutUint64(raw[40:48], 0) // e_shoff
	binary.LittleEndian.PutUint16(raw[60:62], 0) // e_shnum
	_, err := parseELF(raw)
	if err == nil {
		t.Fatal("expected ErrNoSections")
	}
}

func TestParseRejectsNotELF(t *testing.T) {
	_, err := parseELF([]byte("not elf"))
	if err == nil {
		t.Fatal("expected ErrNotELF")
	}
}

func TestMalformedELFDoesNotPanic(t *testing.T) {
	mutateShdr := func(raw []byte, index int, fieldOffset int, value uint64) {
		shoff := binary.LittleEndian.Uint64(raw[40:48])
		offset := int(shoff) + index*64 + fieldOffset
		binary.LittleEndian.PutUint64(raw[offset:offset+8], value)
	}

	tests := map[string]func([]byte){
		"program header offset overflows": func(raw []byte) {
			binary.LittleEndian.PutUint64(raw[32:40], ^uint64(0)-55)
		},
		"section header offset overflows": func(raw []byte) {
			binary.LittleEndian.PutUint64(raw[40:48], ^uint64(0)-63)
		},
		"section data range overflows": func(raw []byte) {
			mutateShdr(raw, 2, 24, ^uint64(0))
			mutateShdr(raw, 2, 32, 2)
		},
		"extended section count exceeds limit": func(raw []byte) {
			binary.LittleEndian.PutUint16(raw[60:62], 0)
			mutateShdr(raw, 0, 32, 1<<58)
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			raw := buildMinimalELF64(t)
			mutate(raw)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parseELF panicked: %v", recovered)
				}
			}()
			if _, err := parseELF(raw); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestParseELFNoteRejectsOverflowingNameSize(t *testing.T) {
	note := make([]byte, 13)
	binary.LittleEndian.PutUint32(note[0:4], ^uint32(0))
	binary.LittleEndian.PutUint32(note[4:8], 1)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("parseELFNote panicked: %v", recovered)
		}
	}()
	if _, err := parseELFNote(binary.LittleEndian, note); err == nil {
		t.Fatal("expected parse error")
	}
}

func FuzzParseELFDoesNotPanic(f *testing.F) {
	f.Add([]byte("not elf"))
	f.Add([]byte("\x7fELF"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseELF(data)
	})
}

// buildMinimalELF64 constructs a tiny ELF64 LE image with .text, .shstrtab and
// a null section — enough for hash/signature rewrite tests.
func buildMinimalELF64(t *testing.T) []byte {
	t.Helper()
	bo := binary.LittleEndian

	shstrtab := []byte{0, '.', 't', 'e', 'x', 't', 0, '.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', 0}
	text := []byte{0x90, 0x90, 0xC3} // nop nop ret

	const (
		ehsize    = 64
		phentsize = 56
		shentsize = 64
		phnum     = 1
		shnum     = 3
	)

	phoff := uint64(ehsize)
	textOff := phoff + uint64(phnum*phentsize)
	shstrOff := textOff + uint64(len(text))
	shoff := shstrOff + uint64(len(shstrtab))

	size := int(shoff) + shnum*shentsize
	buf := make([]byte, size)

	// ELF header
	copy(buf[0:4], []byte(elfMagic))
	buf[4] = eiClassELF64
	buf[5] = eiDataLE
	buf[6] = evCurrent
	bo.PutUint16(buf[16:18], 2)    // ET_EXEC
	bo.PutUint16(buf[18:20], 0x3e) // EM_X86_64
	bo.PutUint32(buf[20:24], 1)
	bo.PutUint64(buf[24:32], 0x400000+textOff) // entry
	bo.PutUint64(buf[32:40], phoff)
	bo.PutUint64(buf[40:48], shoff)
	bo.PutUint16(buf[52:54], ehsize)
	bo.PutUint16(buf[54:56], phentsize)
	bo.PutUint16(buf[56:58], phnum)
	bo.PutUint16(buf[58:60], shentsize)
	bo.PutUint16(buf[60:62], shnum)
	bo.PutUint16(buf[62:64], 2) // shstrndx = .shstrtab

	// Program header covering .text
	ph := buf[phoff : phoff+phentsize]
	bo.PutUint32(ph[0:4], 1) // PT_LOAD
	bo.PutUint32(ph[4:8], 5) // PF_R|PF_X
	bo.PutUint64(ph[8:16], textOff)
	bo.PutUint64(ph[16:24], 0x400000+textOff)
	bo.PutUint64(ph[24:32], 0x400000+textOff)
	bo.PutUint64(ph[32:40], uint64(len(text)))
	bo.PutUint64(ph[40:48], uint64(len(text)))
	bo.PutUint64(ph[48:56], 0x1000)

	copy(buf[textOff:], text)
	copy(buf[shstrOff:], shstrtab)

	writeShdr := func(i int, sh elf64Shdr) {
		off := int(shoff) + i*shentsize
		copy(buf[off:], encodeShdr(bo, sh))
	}
	writeShdr(0, elf64Shdr{}) // null
	writeShdr(1, elf64Shdr{
		Name:      1, // .text
		Type:      1, // SHT_PROGBITS
		Flags:     6, // ALLOC|EXEC
		Addr:      0x400000 + textOff,
		Offset:    textOff,
		Size:      uint64(len(text)),
		Addralign: 1,
	})
	writeShdr(2, elf64Shdr{
		Name:      7, // .shstrtab
		Type:      3, // SHT_STRTAB
		Offset:    shstrOff,
		Size:      uint64(len(shstrtab)),
		Addralign: 1,
	})

	return buf
}
