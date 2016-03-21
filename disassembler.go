package main

// http://wiki.osdev.org/ELF
// http://eli.thegreenplace.net/2011/02/07/how-debuggers-work-part-3-debugging-information/

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"strings"

	"github.com/bnagy/gapstone"
)

type Disassembler struct {
	f         *elf.File
	sourcemap map[string]map[int]string
	entries   map[uint64]*dwarf.LineEntry
}

func New() *Disassembler {
	return &Disassembler{
		sourcemap: map[string]map[int]string{},
		entries:   map[uint64]*dwarf.LineEntry{},
	}
}

func (d *Disassembler) Open(name string) error {
	if f, err := elf.Open(name); err != nil {
		return err
	} else {
		d.f = f
	}

	return d.readDwarf()
}

func (d *Disassembler) readDwarf() error {
	dw, err := d.f.DWARF()
	if err != nil {
		return err
	}

	dwr := dw.Reader()
	for {
		entry, err := dwr.Next()
		if err != nil {
			return err
		} else if entry == nil {
			break
		}

		lr, err := dw.LineReader(entry)
		if err != nil {
			return err
		} else if lr == nil {
			continue
		}

		for {
			le := new(dwarf.LineEntry)

			err := lr.Next(le)
			if err != nil {
				break
			}

			d.entries[le.Address] = le
		}
	}

	return nil
}

func (d *Disassembler) Source(le *dwarf.LineEntry) (string, error) {
	if _, ok := d.sourcemap[le.File.Name]; !ok {
		sm := map[int]string{}

		name := le.File.Name
		name = strings.Replace(name, "/vagrant/signatures/", "./", -1)

		lf, err := os.Open(name)
		if err != nil {
			return "", err
		}

		defer lf.Close()

		line := 0

		scanner := bufio.NewScanner(lf)
		for scanner.Scan() {
			sm[line] = scanner.Text()
			line++
		}

		if err := scanner.Err(); err != nil {
			return "", err
		}

		d.sourcemap[le.File.Name] = sm
	}

	return d.sourcemap[le.File.Name][le.Line], nil
}

func (d *Disassembler) Disasm(addr uint64) error {
	s := d.f.Section(".text")

	if addr == 0 {
		addr = s.Addr
	}

	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_32,
	)
	if err != nil {
		return err
	}

	defer engine.Close()

	data, err := s.Data()
	if err != nil {
		return err
	}

	insns, err := engine.Disasm(
		data, // code buffer
		addr, // starting address
		0,    // insns to disassemble, 0 for all
	)
	if err != nil {
		return err
	}

	for _, insn := range insns {
		fmt.Printf("0x%-7x: %-16x %-40s", insn.Address, insn.Bytes, fmt.Sprintf("%s %s", insn.Mnemonic, insn.OpStr))

		if entry, ok := d.entries[uint64(insn.Address)]; !ok {
		} else if val, err := d.Source(entry); err == nil {
			fmt.Printf("; %s:%d: %s", entry.File.Name, entry.Line, val)
		}

		fmt.Printf("\n")

	}

	return nil
}

func (d *Disassembler) Close() error {
	if d.f != nil {
		d.f.Close()
	}

	return nil
}
