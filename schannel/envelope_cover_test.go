package schannel

import (
	"encoding/binary"
	"testing"

	"github.com/kisom/sbuf"
)

// This package exercises the envelope code to 100%.

var oversized = make([]byte, BufSize+1)

// utility function to construct arbitrary packed messages
func testPackMessage(length, sequence uint32, v uint8, pad uint16, mType MessageType, message []byte) []byte {
	buf := sbuf.NewBuffer(messageOverhead + len(message))
	buf.WriteByte(v)
	buf.WriteByte(uint8(mType))
	binary.Write(buf, binary.BigEndian, pad)

	// An sbuf won't fail to write unless it's out of memory, then this
	// whole house of cards is coming crashing down anyways.
	binary.Write(buf, binary.BigEndian, sequence)
	binary.Write(buf, binary.BigEndian, length)
	buf.Write(message)
	return buf.Bytes()
}

func TestInvalidPack(t *testing.T) {
	_, ok := packMessage(0, NormalMessage, []byte{1})
	if ok {
		t.Fatal("expected packMessage to fail with invalid sequence number")
	}

	_, ok = packMessage(1, NormalMessage, nil)
	if ok {
		t.Fatal("expected packMessage to fail with nil message")
	}

	_, ok = packMessage(1, NormalMessage, []byte{})
	if ok {
		t.Fatal("expected packMessage to fail with empty message")
	}

	var i MessageType
	for i = 0; i < 255; i++ {
		_, ok = packMessage(1, i, []byte{1})
		switch i {
		case NormalMessage, KEXMessage, ShutdownMessage:
			if !ok {
				t.Fatal("expected packMessage to succeed with type ", i)
			}
		default:
			if ok {
				t.Fatal("expected packMessage to fail with an invalid message type")
			}
		}
	}

	if _, ok = packMessage(1, NormalMessage, oversized); ok {
		t.Fatal("expected packMessage to fail with oversized message")
	}
}

func TestInvalidUnpack(t *testing.T) {
	ensureFails := func(in []byte, m string) {
		if _, ok := unpackMessage(in); ok {
			t.Fatalf("expected unpackMessage to fail with %s", m)
		}
	}

	m := []byte{1}

	var in = make([]byte, messageOverhead-1)
	ensureFails(in, "short message")

	out, _ := packMessage(1, NormalMessage, m)
	out[0] = 0
	ensureFails(out, "short message")

	var i MessageType
	for i = 0; i < 255; i++ {
		out = testPackMessage(1, 1, currentVersion, 0, i, m)
		switch i {
		case NormalMessage, KEXMessage, ShutdownMessage:
			_, ok := unpackMessage(out)
			if !ok {
				t.Fatal("expected unpackMessage to succeed with type ", i)
			}
		default:
			ensureFails(out, "invalid message type")
		}
	}

	var p uint16
	for p = 1; p != 0; p++ {
		out = testPackMessage(1, 1, currentVersion, p, NormalMessage, m)
		ensureFails(out, "invalid padding")
	}

	out = testPackMessage(0, 1, currentVersion, 0, NormalMessage, m)
	ensureFails(out, "zero length")

	out = testPackMessage(BufSize+1, 1, currentVersion, 0, NormalMessage, m)
	ensureFails(out, "oversized message")

	out = testPackMessage(2, 1, currentVersion, 0, NormalMessage, m)
	ensureFails(out, "invalid length")
}
