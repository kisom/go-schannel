package schannel

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/agl/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// nonceSize is the size of a NaCl nonce.
	nonceSize  = 24
	kexPubSize = 64
	kexPrvSize = 64
)

var prng = rand.Reader

const (
	// BufSize is the maximum size of an encrypted message.
	BufSize = 2097152 // 2MiB: 2 * 1024 * 1024B

	// IdentityPrivateSize is the size of an identity private key.
	IdentityPrivateSize = ed25519.PrivateKeySize

	// IdentityPublicSize is the size of an identity public key.
	IdentityPublicSize = ed25519.PublicKeySize

	// KeySize is the size of a shared encryption key.
	KeySize = 32

	// Overhead is the amount of overhead added to a message
	// when it is encrypted. This is the size of a nonce, MAC,
	// and message envelope.
	Overhead = 106

	// SignatureSize is the length of an identity signature.
	SignatureSize = ed25519.SignatureSize
)

// A Channel is an insecure channel; a secure channel is overlaid on top
// of this channel.
type Channel io.ReadWriter

// An SChannel is a secure channel. It contains separate encryption keys
// for receiving and sending messages, and tracks message numbers to
// prevent forgeries.
type SChannel struct {
	// RData and SData store the amount of data decrypted (received)
	// and encrypted (sent), respectively.
	RData uint64
	SData uint64

	// rctr and sctr store message sequence numbers. rctr stores the
	// last received message number, and sctr stores the last sent
	// message number.
	rctr uint32
	sctr uint32

	// rkey and skey contain the shared receive and send encryption
	// keys, computed via an ECDH exchange.
	rkey [KeySize]byte
	skey [KeySize]byte

	// buf stores the internal buffer used for incoming messages.
	buf [BufSize + Overhead]byte

	// Channel is the insecure channel the SChannel is built on.
	Channel Channel

	// ready is set to true when the SChannel is established and
	// fully set up.
	ready bool

	// kexip is used to track when a key exchange is in progress.
	kexip bool
}

// RCtr returns the last received message counter.
func (sch *SChannel) RCtr() uint32 {
	return sch.rctr
}

// SCtr returns the last sent message counter.
func (sch *SChannel) SCtr() uint32 {
	return sch.sctr
}

// Ready returns true if the secure channel is ready to send or receive
// messages. If it returns false, the secure channel should be zeroised
// and discarded.
func (sch *SChannel) Ready() bool {
	return sch.ready
}

func (sch *SChannel) resetCounters() {
	if sch == nil {
		return
	}

	sch.RData = 0
	sch.SData = 0
	sch.rctr = 0
	sch.sctr = 0
}

func (sch *SChannel) reset() {
	if sch == nil {
		return
	}

	sch.resetCounters()
	sch.ready = false
	sch.kexip = false
	sch.Channel = nil
	zero(sch.buf[:], 0)
	zero(sch.rkey[:], 0)
	zero(sch.skey[:], 0)
}

func generateKeypair(sk *[kexPrvSize]byte, pk *[kexPubSize]byte) bool {
	if sk == nil || pk == nil {
		return false
	}

	pub, priv, err := box.GenerateKey(prng)
	if err != nil {
		return false
	}

	copy(sk[:], priv[:])
	zero(priv[:], 0)
	copy(pk[:], pub[:])

	pub, priv, err = box.GenerateKey(prng)
	if err != nil {
		zero(sk[:], 0)
		return false
	}

	copy(sk[32:], priv[:])
	zero(priv[:], 0)
	copy(pk[32:], pub[:])
	return true
}

func signKEX(kex *[kexPubSize + SignatureSize]byte, signer *[IdentityPrivateSize]byte) bool {
	if kex == nil {
		return false
	}

	if signer == nil {
		return true
	}

	sig := ed25519.Sign(signer, kex[:kexPubSize])
	copy(kex[kexPubSize:], sig[:])
	return true
}

func verifyKEX(kex *[kexPubSize + SignatureSize]byte, peer *[IdentityPublicSize]byte) bool {
	if kex == nil {
		return false
	}

	if peer == nil {
		return true
	}

	var sig = new([SignatureSize]byte)
	copy(sig[:], kex[kexPubSize:])
	return ed25519.Verify(peer, kex[:kexPubSize], sig)
}

// keyExchange is a convenience function that takes keys as byte slices,
// copying them into the appropriate arrays.
func keyExchange(shared *[32]byte, priv, pub []byte) {
	// Copy the private key and wipe it, as it will no longer be needed.
	var kexPriv [32]byte
	copy(kexPriv[:], priv)
	zero(priv, 0)

	var kexPub [32]byte
	copy(kexPub[:], pub)
	box.Precompute(shared, &kexPub, &kexPriv)

	zero(kexPriv[:], 0)
}

func (sch *SChannel) doKEX(sk []byte, pk []byte, dialer bool) bool {
	if sk == nil || pk == nil {
		return false
	} else if len(sk) != kexPrvSize || len(pk) != kexPubSize {
		return false
	}

	// This function denotes the dialer, who initiates the session,
	// as A. The listener is denoted as B. A is started using Dial,
	// and B is started using Listen.
	if dialer {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// A send key.
		keyExchange(&sch.skey, sk[:32], pk[:32])
		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the A
		// receive key.
		keyExchange(&sch.rkey, sk[32:], pk[32:])
	} else {
		// The first 32 bytes are the A->B link, where A is the
		// dialer. This key material should be used to set up the
		// B receive key.
		keyExchange(&sch.rkey, sk[:32], pk[:32])
		// The last 32 bytes are the B->A link, where A is the
		// dialer. This key material should be used to set up the
		// B send key.
		keyExchange(&sch.skey, sk[32:], pk[32:])
	}

	return true
}

// dialKEX handles the initial dialing key exchange.
func (sch *SChannel) dialKEX(ch Channel, signer *[IdentityPrivateSize]byte, peer *[IdentityPublicSize]byte) bool {
	var sk [kexPrvSize]byte
	var pk [kexPubSize]byte

	if !generateKeypair(&sk, &pk) {
		return false
	}

	var kex [kexPubSize + SignatureSize]byte
	copy(kex[:], pk[:])

	if !signKEX(&kex, signer) {
		return false
	}

	n, err := ch.Write(kex[:])
	if err != nil || n != len(kex) {
		return false
	}

	zero(kex[:], 0)
	_, err = io.ReadFull(ch, kex[:])
	if err != nil {
		return false
	}

	if !verifyKEX(&kex, peer) {
		return false
	}

	if !sch.doKEX(sk[:], kex[:kexPubSize], true) {
		return false
	}

	return true
}

// Dial initialise the SChannel and initiate a key exchange over the
// Channel. If this returns true, an authenticated secure channel has
// been established. If signer is not nil, the key exchange will be
// signed with the key it contains. If peer is not nil, the key exchange
// will be verified using the public key it contains.
func Dial(ch Channel, signer *[IdentityPrivateSize]byte, peer *[IdentityPublicSize]byte) (*SChannel, bool) {
	var sch = &SChannel{}
	sch.reset()

	if ch == nil {
		return nil, false
	}

	if !sch.dialKEX(ch, signer, peer) {
		return nil, false
	}

	sch.Channel = ch
	sch.ready = true
	return sch, true
}

func (sch *SChannel) listenKEX(ch Channel, signer *[IdentityPrivateSize]byte, peer *[IdentityPublicSize]byte) bool {
	var sk [kexPrvSize]byte
	var pk [kexPubSize]byte

	if !generateKeypair(&sk, &pk) {
		return false
	}

	var kex [kexPubSize + SignatureSize]byte
	_, err := io.ReadFull(ch, kex[:])
	if err != nil {
		return false
	}

	if !verifyKEX(&kex, peer) {
		return false
	}

	if !sch.doKEX(sk[:], kex[:kexPubSize], false) {
		return false
	}

	copy(kex[:], pk[:])
	if !signKEX(&kex, signer) {
		return false
	}

	n, err := ch.Write(kex[:])
	if err != nil || n != len(kex) {
		return false
	}
	zero(kex[:], 0)

	return true
}

// Listen initialises the SChannel and complete a key exchange over
// the Channel. If this returns true, an authenticated secure channel has
// been established. If signer is not nil, the key exchange will be
// signed with the key it contains. If peer is not nil, the key exchange
// will be verified using the public key it contains.
func Listen(ch Channel, signer *[IdentityPrivateSize]byte, peer *[IdentityPublicSize]byte) (*SChannel, bool) {
	var sch = &SChannel{}
	sch.reset()

	if ch == nil {
		return nil, false
	}

	if !sch.listenKEX(ch, signer, peer) {
		return nil, false
	}

	sch.Channel = ch
	sch.ready = true
	return sch, true
}

func (sch *SChannel) encrypt(m []byte) ([]byte, bool) {
	out := make([]byte, nonceSize, nonceSize+len(m))
	var nonce [nonceSize]byte
	_, err := io.ReadFull(prng, nonce[:])
	if err != nil {
		return nil, false
	}

	copy(out, nonce[:])
	return secretbox.Seal(out, m, &nonce, &sch.skey), true
}

func (sch *SChannel) send(t MessageType, m []byte) bool {
	sch.sctr++
	out, ok := packMessage(sch.sctr, t, m)
	if !ok {
		return false
	}

	enc, ok := sch.encrypt(out)
	zero(out, 0)
	if !ok {
		return false
	}
	sch.SData += uint64(len(out))

	err := binary.Write(sch.Channel, binary.BigEndian, uint32(len(enc)))
	if err != nil {
		return false
	}

	_, err = sch.Channel.Write(enc)
	if err != nil {
		return false
	}

	return true
}

// Send seals the message and sends it over the secure channel.
func (sch *SChannel) Send(m []byte) bool {
	if !sch.ready {
		return false
	}
	return sch.send(NormalMessage, m)
}

// Message pairs a message type with contents.
type Message struct {
	Type     MessageType
	Contents []byte
}

func (sch *SChannel) decrypt(in []byte) ([]byte, bool) {
	if len(in) <= nonceSize {
		return nil, false
	}

	var nonce [nonceSize]byte
	copy(nonce[:], in[:nonceSize])
	return secretbox.Open(nil, in[nonceSize:], &nonce, &sch.rkey)
}

func (sch *SChannel) getMessage() ([]byte, bool) {
	var mlen uint32
	err := binary.Read(sch.Channel, binary.BigEndian, &mlen)
	if err != nil {
		return nil, false
	}

	if mlen > BufSize+Overhead {
		return nil, false
	}

	_, err = io.ReadFull(sch.Channel, sch.buf[:int(mlen)])
	if err != nil {
		return nil, false
	}

	out, ok := sch.decrypt(sch.buf[:int(mlen)])
	if !ok {
		return nil, false
	}

	zero(sch.buf[:], int(mlen))
	sch.RData += uint64(len(out))
	return out, true
}

func (sch *SChannel) extractMessage(in []byte) (*Message, bool) {
	e, ok := unpackMessage(in)
	if !ok {
		return nil, false
	}

	if e.Sequence <= sch.rctr {
		return nil, false
	}
	sch.rctr = e.Sequence

	switch e.Type {
	case NormalMessage:
		// Do nothing
	case KEXMessage:
		if sch.kexip {
			break
		}

		if !(sch.receiveKEX(e)) {
			return nil, false
		}

		return &Message{Type: KEXMessage}, true
	case ShutdownMessage:
		// The contents of this message are irrelevant.
		return &Message{Type: ShutdownMessage}, true
	default:
		return nil, false
	}

	m := &Message{
		Type: e.Type,
	}
	m.Contents = make([]byte, int(e.PayloadLength))
	copy(m.Contents, e.Payload[:])
	zero(e.Payload[:], int(e.PayloadLength))
	return m, true
}

// Receive reads a new message from the secure channel.
func (sch *SChannel) Receive() (*Message, bool) {
	if !sch.ready {
		return nil, false
	}

	out, ok := sch.getMessage()
	if !ok {
		return nil, false
	}

	return sch.extractMessage(out)
}

func (sch *SChannel) receiveKEX(e *envelope) bool {
	if e == nil || sch.kexip || !sch.ready {
		return false
	}

	if kexPubSize != int(e.PayloadLength) {
		return false
	}

	var sk [kexPrvSize]byte
	var pk [kexPubSize]byte

	if !generateKeypair(&sk, &pk) {
		return false
	}

	if !sch.send(KEXMessage, pk[:]) {
		return false
	}

	if !sch.doKEX(sk[:], e.Payload[:kexPubSize], false) {
		return false
	}

	return true
}

// Close signals the other end of the secure channel that the channel
// is being closed, and calls Zero to zeroise the secure channel. After
// this, the caller should close the underlying channel as appropriate.
func (sch *SChannel) Close() bool {
	if sch == nil {
		return false
	} else if !sch.ready {
		return false
	}

	defer sch.Zero()
	return sch.send(ShutdownMessage, []byte{0})
}

// Zero zeroises the channel, wiping the shared keys from memory and resetting
// the channel. After this is called, the secure channel cannot be used for
// anything else.
func (sch *SChannel) Zero() {
	if sch == nil {
		return
	}

	zero(sch.skey[:], 0)
	zero(sch.rkey[:], 0)
	sch.reset()
}

// Rekey initiates a key rotation with the other side. Both sides will
// generate new session private keys, and exchange their public
// halves. These session keys will not be signed, as the channel is
// assumed to be authenticated and secure at this point. Generally,
// key rotation will not be an issue. However, peers may elect to
// rekey after a certain time period, a certain number of messages
// have been sent, or a certain amount of data will be sent.
func (sch *SChannel) Rekey() bool {
	if !sch.ready {
		return false
	}

	var sk [kexPrvSize]byte
	var pk [kexPubSize]byte

	if !generateKeypair(&sk, &pk) {
		return false
	}

	if !sch.send(KEXMessage, pk[:]) {
		return false
	}

	sch.kexip = true
	m, ok := sch.Receive()
	if !ok || m.Type != KEXMessage {
		return false
	}
	sch.kexip = false

	if !sch.doKEX(sk[:], m.Contents, true) {
		return false
	}

	return true
}
