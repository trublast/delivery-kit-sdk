package inhouse

import (
	"encoding/binary"
	"fmt"
)

const (
	signatureSectionName = ".note.delivery-kit.signature"
	signatureNoteName    = "delivery-kit.signature"
	signatureNoteType    = 0x31415926
	bsignSectionName     = "signature"
	shstrtabSectionName  = ".shstrtab"
)

func createELFNote(bo binary.ByteOrder, name string, desc []byte, noteType uint32) []byte {
	nameBytes := append([]byte(name), 0)
	nameSize := uint32(len(nameBytes))
	descSize := uint32(len(desc))
	namePadded := (nameSize + 3) &^ 3
	descPadded := (descSize + 3) &^ 3
	total := 12 + namePadded + descPadded

	buf := make([]byte, total)
	bo.PutUint32(buf[0:4], nameSize)
	bo.PutUint32(buf[4:8], descSize)
	bo.PutUint32(buf[8:12], noteType)
	copy(buf[12:], nameBytes)
	if descSize > 0 {
		copy(buf[12+namePadded:], desc)
	}
	return buf
}

type elfNote struct {
	Name string
	Desc []byte
	Type uint32
}

func parseELFNote(bo binary.ByteOrder, data []byte) (*elfNote, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("note data size too small for ELF note header")
	}

	nameSize := bo.Uint32(data[0:4])
	descSize := bo.Uint32(data[4:8])
	noteType := bo.Uint32(data[8:12])
	if nameSize == 0 {
		return nil, fmt.Errorf("note name size is zero")
	}

	namePadded := (uint64(nameSize) + 3) &^ uint64(3)
	descOffset := uint64(12) + namePadded
	if !rangeWithinFile(12, namePadded, len(data)) {
		return nil, fmt.Errorf("note name out of bounds")
	}
	if !rangeWithinFile(descOffset, uint64(descSize), len(data)) {
		return nil, fmt.Errorf("note descriptor out of bounds")
	}

	nameEnd := 12 + int(nameSize)
	name := data[12:nameEnd]
	if len(name) > 0 && name[len(name)-1] == 0 {
		name = name[:len(name)-1]
	}

	var desc []byte
	if descSize > 0 {
		desc = append([]byte(nil), data[int(descOffset):int(descOffset)+int(descSize)]...)
	}

	return &elfNote{
		Name: string(name),
		Desc: desc,
		Type: noteType,
	}, nil
}
