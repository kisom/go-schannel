// Package schannel establishes bidirectional secure channels over TCP/IP.
//
// This package is a port of libschannel (https://github.com/kisom/libschannel)
// to Go. For details on the protocol and the properties of a secure channel,
// the libschannel documentation should be consulted. Secure channels use
// Curve25519 ECDH to exchange NaCl secretbox keys, and Ed25519 to sign key
// exchanges.
//
// A secure channel is established with the Dial and Listen functions: one
// side called Dial to set up a key exchange with the other side, and the
// other side calls Listen to finalise the key exchange. For example, the
// client might have the following:
//
//	conn, err := net.Dial("tcp", host)
//	die.If(err)
//	defer conn.Close()
//
//	sch, ok := schannel.Dial(conn, idPriv, idPeer)
//	if !ok {
//		die.With("failed to set up secure channel")
//	}
//	fmt.Println("secure channel established")
//
// On the server side, the code might look like this:
//	ln, err := net.Listen("tcp", ":"+port)
//	die.If(err)
//
//	fmt.Println("Listening on", ":"+port)
//	for {
//		conn, err := ln.Accept()
//		if err != nil {
//			fmt.Printf("Connection error: %v\n", err)
//			continue
//		}
//		sch, ok := schannel.Listen(conn, idPriv, idPeer)
//		if !ok {
//			log.Printf("failed to establish secure channel")
//		}
//		log.Printf("secure channel established")
//		go run session(sch)
//	}
//
// Authentication is done using identity signature keys. These keys must
// be known ahead of time, and key distribution is not a part of this
// library. Each side chooses whether to sign and/or verify the signature
// on the key exchange by providing an appropriate key or a nil key.
//
// The two pairs may send messages over the secure channel using the Send
// function. These messages may be received with the Receive function,
// which returns a *Message that pairs the message type with the message
// contents.
//
// If the message is a NormalMessage, the contents will contain the original
// message that was sent. If it is a KEXMessage or ShutdownMessage, the
// contents will be empty. In the case of a KEXMessage, the receiver does not
// need to do anything: it indicates that a key rotation took place, and is
// provided for informational purposes. However, if the message is a
// ShutdownMessage, the receiver should call the Zero method on the secure
// channel.
package schannel
