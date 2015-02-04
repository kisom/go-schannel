// schannel_keygen generates identity keypairs for use with schannel.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/agl/ed25519"
	"github.com/kisom/die"
)

func usage() {
	progName := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `%s version 1.0
Usage:
	%s basenames...
		This program will output a pair of files for each basename:
			- basename.key: private signature (identity key)
			- basename.pub: public signature (identity key)

		These files will be in the binary form that can be
		directly loaded into the schannel_dial and schannel_listen
		functions.

`, progName, progName)
}

func main() {
	showHelp := flag.Bool("h", false, "display a short usage message and exit")
	flag.Parse()

	if *showHelp {
		usage()
		os.Exit(0)
	}

	if flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}

	for _, baseName := range flag.Args() {
		pubFileName := fmt.Sprintf("%s.pub", baseName)
		privFileName := fmt.Sprintf("%s.key", baseName)

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		die.If(err)

		err = ioutil.WriteFile(pubFileName, pub[:], 0644)
		die.If(err)

		err = ioutil.WriteFile(privFileName, priv[:], 0600)
		die.If(err)
	}
}
