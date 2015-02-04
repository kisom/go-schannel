package schannel

import (
	"bytes"
	"testing"
)

func TestEnvelopeBasic(t *testing.T) {
	m := []byte("do not go gentle into that good night")
	out, ok := packMessage(1, NormalMessage, m)
	if !ok {
		t.Fatal("Failed to pack message.")
	}

	e, ok := unpackMessage(out)
	if !ok {
		t.Fatal("Failed to unpack message.")
	}

	if e.Type != NormalMessage {
		t.Fatalf("Invalid message type: expected %d, have %d.",
			NormalMessage, e.Type)
	}

	if e.Pad != 0 {
		t.Fatal("Invalid padding on message.")
	}

	if e.Sequence != 1 {
		t.Fatal("Invalid sequence number on message.")
	}

	if int(e.PayloadLength) != len(m) {
		t.Fatal("Invalid payload length.")
	}

	if !bytes.Equal(m, e.Payload[:e.PayloadLength]) {
		t.Fatal("Invalid payload.")
	}
}
