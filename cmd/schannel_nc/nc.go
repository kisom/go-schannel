// schannel_nc is a netcat-like program that communicates with secure channels.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/kisom/die"
	"github.com/kisom/go-schannel/schannel"
)

var (
	idPriv *[64]byte
	idPub  *[32]byte
)

func usage() {
	progName := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `%s version 1.0
Usage:

%s  [-hk] [-s signer] [-v verifier] host port
%s [-hkl] [-s signer] [-v verifier] port
        -h              print this usage message and exit
        -k              force the program to keep listening after the client
                        disconnects. This must be used with -l.
        -l              listen for an incoming connection
        -s signer       specify the path to a signature key
        -v verifier     specify the path to a verification key

If a signature key is specified, it will be used to sign the key exchange. If a
verification key is specified, it will be used to verify the signature on the
key exchange.
`, progName, progName, progName)
}

func zero(in []byte, n int) {
	if in == nil {
		return
	}

	stop := n
	if stop > len(in) || stop == 0 {
		stop = len(in)
	}

	for i := 0; i < stop; i++ {
		in[i] ^= in[i]
	}
}

func loadID(privName, pubName string) {
	if pubName != "" {
		pubFile, err := os.Open(pubName)
		die.If(err)
		defer pubFile.Close()

		idPub = new([32]byte)
		_, err = io.ReadFull(pubFile, idPub[:])
		die.If(err)
	}

	if privName != "" {
		privFile, err := os.Open(privName)
		die.If(err)
		defer privFile.Close()

		idPriv = new([64]byte)
		_, err = io.ReadFull(privFile, idPriv[:])
		die.If(err)
	}
}

func listener(stayOpen bool, port string) {
	ln, err := net.Listen("tcp", ":"+port)
	die.If(err)

	fmt.Println("Listening on", ":"+port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("Connection error: %v\n", err)
			continue
		}

		newChannel(conn)
		if !stayOpen {
			break
		}
	}
}

func newChannel(conn net.Conn) {
	defer conn.Close()
	sch, ok := schannel.Listen(conn, idPriv, idPub)
	if !ok {
		log.Printf("failed to establish secure channel")
		return
	}

	var stop bool
	log.Printf("secure channel established")
	for {
		m, ok := sch.Receive()
		if !ok {
			log.Printf("receive failed")
			break
		}

		switch m.Type {
		case schannel.ShutdownMessage:
			log.Printf("peer is shutting down")
			stop = true
			break
		case schannel.KEXMessage:
			log.Printf("keys rotated")
		case schannel.NormalMessage:
			os.Stdout.Write(m.Contents)
		default:
			log.Printf("unknown message type received: %d", m.Type)
		}

		if stop {
			break
		}
	}

	rcvd := sch.RCtr()
	if stop {
		rcvd--
	}
	log.Printf("received %d messages with %d bytes", rcvd, sch.RData)
	log.Print("zeroising secure channel")
	sch.Zero()
	log.Print("secure channel shutdown")
}

func sender(host string) {
	conn, err := net.Dial("tcp", host)
	die.If(err)
	defer conn.Close()

	sch, ok := schannel.Dial(conn, idPriv, idPub)
	if !ok {
		die.With("failed to set up secure channel")
	}
	fmt.Println("secure channel established")

	if !sch.Rekey() {
		die.With("rekey failed")
	}

	for {
		var p = make([]byte, 8192)
		n, err := os.Stdin.Read(p)
		if err == io.EOF {
			break
		}
		die.If(err)

		if !sch.Send(p[:n]) {
			die.With("failed to send message (sdata=%d, sctr=%d)",
				sch.SData, sch.SCtr)
		}
	}

	sctr := sch.SCtr()
	sdata := sch.SData
	if !sch.Close() {
		die.With("failed to shutdown channel properly")
	}
	fmt.Println("Secure channel tore down")
	fmt.Printf("\t%d messages totalling %d bytes sent\n",
		sctr, sdata)

	return
}

func main() {
	var pubFile, privFile string
	var help, listen, stayOpen bool
	flag.BoolVar(&help, "h", false, "display a short usage message")
	flag.BoolVar(&stayOpen, "k", false, "keep listening after client disconnects")
	flag.BoolVar(&listen, "l", false, "listen for incoming connections")
	flag.StringVar(&privFile, "s", "", "path to signature key")
	flag.StringVar(&pubFile, "v", "", "path to verification key")
	flag.Parse()

	if help {
		usage()
		os.Exit(1)
	}

	loadID(privFile, pubFile)
	defer func() {
		if idPriv != nil {
			zero(idPriv[:], 0)
		}
	}()

	if listen {
		if flag.NArg() != 1 {
			fmt.Println("A port is required (and should be the only argument) when listening.")
		}
		listener(stayOpen, flag.Arg(0))
		return
	}

	if flag.NArg() != 2 {
		fmt.Println("An address and port are required (and should be the only arguments).")
	}
	sender(flag.Arg(0) + ":" + flag.Arg(1))
}
