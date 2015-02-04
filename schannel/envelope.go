package schannel

import (
	"encoding/binary"

	"github.com/kisom/sbuf"
)

// A MessageType represents a type of message.
type MessageType uint8

const (
	// InvalidMessage is any message that is invalid.
	InvalidMessage MessageType = iota

	// NormalMessage is a normal message.
	NormalMessage

	// KEXMessage is a key exchange message.
	KEXMessage

	// ShutdownMessage is an indication that the secure channel
	// should be shut down.
	ShutdownMessage
)

// An envelope is used to wrap a message before encryption.
type envelope struct {
	// Version stores the message format version.
	Version uint8

	// Type contains the message type.
	Type MessageType

	// Pad contains two bytes of padding.
	Pad uint16

	// Sequence contains the message sequence number.
	Sequence uint32

	// PayloadLength contains the length of the payload.
	PayloadLength uint32

	// Payload contains the message being sent.
	Payload [BufSize]byte
}

const (
	currentVersion  = 1
	messageOverhead = 12 // 2 * uint32 + 2 * uint8 + uint16
)

// packMessage serialises the message into a byte slice.
func packMessage(sequence uint32, mType MessageType, message []byte) ([]byte, bool) {
	if sequence == 0 {
		return nil, false
	}

	if len(message) == 0 || len(message) > BufSize {
		return nil, false
	}

	switch mType {
	case NormalMessage:
	case KEXMessage:
	case ShutdownMessage:
	default:
		return nil, false
	}

	buf := sbuf.NewBuffer(messageOverhead + len(message))
	buf.WriteByte(currentVersion)
	buf.WriteByte(uint8(mType))
	buf.WriteByte(0) // padding
	buf.WriteByte(0) // padding

	// An sbuf won't fail to write unless it's out of memory, then this
	// whole house of cards is coming crashing down anyways.
	binary.Write(buf, binary.BigEndian, sequence)
	binary.Write(buf, binary.BigEndian, uint32(len(message)))
	buf.Write(message)
	return buf.Bytes(), true
}

// unpackMessage unpacks a byte slice into a message.
func unpackMessage(in []byte) (*envelope, bool) {
	var e envelope

	if len(in) <= messageOverhead {
		return nil, false
	}

	buf := sbuf.NewBufferFrom(in)
	defer buf.Close()

	// ReadByte won't fail given our length check at the beginning.
	e.Version, _ = buf.ReadByte()
	if e.Version != currentVersion {
		return nil, false
	}

	c, _ := buf.ReadByte()
	e.Type = MessageType(c)
	switch e.Type {
	case NormalMessage:
	case KEXMessage:
	case ShutdownMessage:
	default:
		return nil, false
	}

	// Read won't fail here with an sbuf given our length check.
	binary.Read(buf, binary.BigEndian, &e.Pad)
	if e.Pad != 0 {
		return nil, false
	}

	// Read won't fail here with an sbuf given our length check.
	binary.Read(buf, binary.BigEndian, &e.Sequence)
	binary.Read(buf, binary.BigEndian, &e.PayloadLength)
	if e.PayloadLength == 0 {
		return nil, false
	} else if e.PayloadLength > BufSize {
		return nil, false
	} else if buf.Len() != int(e.PayloadLength) {
		return nil, false
	}

	// Read won't fail here given the previous length checks.
	buf.Read(e.Payload[:int(e.PayloadLength)])
	return &e, true
}
