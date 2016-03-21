package main

import "flag"

func main() {
	flag.Parse()

	d := New()

	if err := d.Open(flag.Args()[0]); err != nil {
		panic(err)
	}

	defer d.Close()

	if err := d.Disasm(0); err != nil {
		panic(err)
	}
}
