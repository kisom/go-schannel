package schannel

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/agl/ed25519"
	"github.com/kisom/testio"
)

var (
	clientSK *[IdentityPrivateSize]byte
	clientPK *[IdentityPublicSize]byte
	serverSK *[IdentityPrivateSize]byte
	serverPK *[IdentityPublicSize]byte
)

func TestGenerateIDKeys(t *testing.T) {
	var err error
	clientPK, clientSK, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}

	serverPK, serverSK, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

var message = []byte(`do not go gentle into that good night
old age should rave and burn at close of day
rage, rage against the dying of the light

though wise men at their end know dark is right
because their words had forked no lightning, they
do not go gentle into that good night

good men, the last wave by, crying how bright
their frail deeds might have danced in a green bay
rage, rage against the dying of the light

wild men, who caught, and sang, the sun in flight
and learned, too late, they grieved it on its way
do not go gentle into that good night

grave men, near death, who see with blinding sight
blind eyes could blaze like meteors and be gay
rage, rage against the dying of the light

and you, my father, there on that sad height
curse, bless, me now, with your fierce tears, i pray
do not go gentle into that good night
rage, rage against the dying of the light
`)

func TestDialNoAuth(t *testing.T) {
	testDial(t, nil, nil, nil, nil, true)
}

func TestDialServerAuth(t *testing.T) {
	testDial(t, nil, nil, serverSK, serverPK, true)
}

func TestDialServerAuthFail(t *testing.T) {
	testDial(t, nil, nil, serverSK, clientPK, false)
}

func TestDialClientAuth(t *testing.T) {
	testDial(t, clientSK, clientPK, nil, nil, true)
}

func TestDialMutualAuth(t *testing.T) {
	testDial(t, clientSK, clientPK, serverSK, serverPK, true)
}

func testDial(t *testing.T, csk *[IdentityPrivateSize]byte, cpk *[IdentityPublicSize]byte, ssk *[IdentityPrivateSize]byte, spk *[IdentityPublicSize]byte, vok bool) {
	ch := testio.NewBufferConn()
	var pub [kexPubSize]byte
	var priv [kexPrvSize]byte

	if !generateKeypair(&priv, &pub) {
		t.Fatal("failed to generate keypair")
	}

	var kex [kexPubSize + SignatureSize]byte
	copy(kex[:], pub[:])
	if !signKEX(&kex, ssk) {
		t.Fatal("failed to sign key exchange")
	}
	ch.WritePeer(kex[:])

	alice, ok := Dial(ch, csk, spk)
	if !ok && vok {
		t.Fatal("failed to set up secure session")
	} else if ok && !vok {
		t.Fatal("secure session shouldn't have been set up")
	}

	if !vok {
		return
	}

	if !alice.Ready() {
		t.Fatal("alice is not ready")
	}

	if alice.RCtr() != 0 || alice.SCtr() != 0 {
		t.Fatal("alice's counters were not reset")
	}

	var peer [kexPubSize + SignatureSize]byte
	_, err := ch.ReadClient(peer[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	ok = verifyKEX(&peer, cpk)
	if !ok && vok {
		t.Fatal("failed to verify key exchange")
	} else if ok && !vok {
		t.Fatal("key exchange verification should fail")
	}

	bob := &SChannel{}
	bob.reset()
	if !bob.doKEX(priv[:], peer[:kexPubSize], false) {
		t.Fatal("doKEX failed")
	}
	bob.ready = true
	buf := &bytes.Buffer{}

	if !bytes.Equal(alice.skey[:], bob.rkey[:]) {
		fmt.Printf("alice send key: %x\n", alice.skey)
		fmt.Printf("  bob recv key: %x\n", bob.rkey)
		t.Fatal("alice and bob have mismatched keys")
	}

	if !bytes.Equal(alice.rkey[:], bob.skey[:]) {
		fmt.Printf("alice recv key: %x\n", alice.rkey)
		fmt.Printf("  bob send key: %x\n", bob.skey)
		t.Fatal("alice and bob have mismatched keys")
	}

	bob.Channel = buf
	alice.Channel = buf

	if !alice.Send(message) {
		t.Fatal("alice failed to send a message")
	}

	// The dread TLA has captured our heroes' secure message!
	tlaCapture := buf.Bytes()

	m, ok := bob.Receive()
	if !ok {
		t.Fatal("bob couldn't receive the message")
	} else if m.Type != NormalMessage {
		t.Fatal("bob got an invalid message")
	} else if !bytes.Equal(m.Contents, message) {
		t.Fatal("bob didn't get the message alice sent")
	}

	for i := 0; i < 32; i++ {
		if !alice.Send(message) {
			t.Fatal("alice failed to send a message")
		}

		m, ok := bob.Receive()
		if !ok {
			t.Fatal("bob couldn't receive the message")
		} else if m.Type != NormalMessage {
			t.Fatal("bob got an invalid message")
		} else if !bytes.Equal(m.Contents, message) {
			t.Fatal("bob didn't get the message alice sent")
		}
	}

	buf.Write(tlaCapture)
	_, ok = bob.Receive()
	if ok {
		t.Fatal("the TLA won!")
	}
	// \o/

	if !alice.Close() {
		t.Fatal("alice couldn't shutdown the channel")
	}

	if m, ok := bob.Receive(); !ok {
		t.Fatal("bob couldn't receive the message")
	} else if m.Type != ShutdownMessage {
		t.Fatal("bob expected a shutdown message")
	}
	bob.Zero()
}

func TestListenNoAuth(t *testing.T) {
	testListen(t, nil, nil, nil, nil, true)
}

func TestListenServerAuth(t *testing.T) {
	testListen(t, nil, nil, serverSK, serverPK, true)
}

func TestListenServerAuthFail(t *testing.T) {
	testListen(t, serverSK, clientPK, nil, nil, false)
}

func TestListenClientAuth(t *testing.T) {
	testListen(t, clientSK, clientPK, nil, nil, true)
}

func TestListenClientAuthFail(t *testing.T) {
	testListen(t, clientSK, serverPK, nil, nil, false)
}

func TestListenMutualAuth(t *testing.T) {
	testListen(t, clientSK, clientPK, serverSK, serverPK, true)
}

func testListen(t *testing.T, csk *[IdentityPrivateSize]byte, cpk *[IdentityPublicSize]byte, ssk *[IdentityPrivateSize]byte, spk *[IdentityPublicSize]byte, vok bool) {
	ch := testio.NewBufferConn()
	var pub [kexPubSize]byte
	var priv [kexPrvSize]byte

	if !generateKeypair(&priv, &pub) {
		t.Fatal("failed to generate keypair")
	}

	var kex [kexPubSize + SignatureSize]byte
	copy(kex[:], pub[:])
	if !signKEX(&kex, csk) {
		t.Fatal("signKEX failed")
	}
	ch.WritePeer(kex[:])

	alice, ok := Listen(ch, ssk, cpk)
	if !ok && vok {
		t.Fatal("failed to set up secure session")
	} else if ok && !vok {
		t.Fatal("secure session shouldn't have been set up")
	}

	if !vok {
		return
	}

	if !alice.Ready() {
		t.Fatal("alice is not ready")
	}

	if alice.RCtr() != 0 || alice.SCtr() != 0 {
		t.Fatal("alice's counters were not reset")
	}

	var peer [kexPubSize + SignatureSize]byte
	_, err := ch.ReadClient(peer[:])
	if err != nil {
		t.Fatalf("%v", err)
	}

	ok = verifyKEX(&peer, spk)
	if !ok && vok {
		t.Fatal("verifyKEX failed")
	} else if ok && !vok {
		t.Fatal("verifyKEX should have failed")
	}

	bob := &SChannel{}
	bob.reset()
	if !bob.doKEX(priv[:], peer[:kexPubSize], true) {
		t.Fatal("doKEX failed")
	}
	bob.ready = true
	buf := &bytes.Buffer{}

	if !bytes.Equal(alice.skey[:], bob.rkey[:]) {
		fmt.Printf("alice send key: %x\n", alice.skey)
		fmt.Printf("  bob recv key: %x\n", bob.rkey)
		t.Fatal("alice and bob have mismatched keys")
	}

	if !bytes.Equal(alice.rkey[:], bob.skey[:]) {
		fmt.Printf("alice recv key: %x\n", alice.rkey)
		fmt.Printf("  bob send key: %x\n", bob.skey)
		t.Fatal("alice and bob have mismatched keys")
	}

	bob.Channel = buf
	alice.Channel = buf

	if !alice.Send(message) {
		t.Fatal("alice failed to send a message")
	}

	// The dread TLA has captured our heroes' secure message!
	tlaCapture := buf.Bytes()

	m, ok := bob.Receive()
	if !ok {
		t.Fatal("bob couldn't receive the message")
	} else if m.Type != NormalMessage {
		t.Fatal("bob got an invalid message")
	} else if !bytes.Equal(m.Contents, message) {
		t.Fatal("bob didn't get the message alice sent")
	}

	for i := 0; i < 32; i++ {
		if !alice.Send(message) {
			t.Fatal("alice failed to send a message")
		}

		m, ok := bob.Receive()
		if !ok {
			t.Fatal("bob couldn't receive the message")
		} else if m.Type != NormalMessage {
			t.Fatal("bob got an invalid message")
		} else if !bytes.Equal(m.Contents, message) {
			t.Fatal("bob didn't get the message alice sent")
		}
	}

	buf.Write(tlaCapture)
	_, ok = bob.Receive()
	if ok {
		t.Fatal("the TLA won!")
	}
	// \o/

	if !alice.Close() {
		t.Fatal("alice couldn't shutdown the channel")
	}

	if m, ok := bob.Receive(); !ok {
		t.Fatal("bob couldn't receive the message")
	} else if m.Type != ShutdownMessage {
		t.Fatal("bob expected a shutdown message")
	}
	bob.Zero()
}
