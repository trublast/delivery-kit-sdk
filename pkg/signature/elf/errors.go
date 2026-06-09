package elf

import "errors"

var (
	ErrNotELF             = errors.New("not an ELF file")
	ErrNoSections         = errors.New("ELF file has no section headers")
	ErrNoSignatureSection = errors.New("no signature section")
)
