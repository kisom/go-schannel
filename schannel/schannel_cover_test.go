package schannel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// This package provides additional exercising of the code.

func TestResetNil(t *testing.T) {
	var sch *SChannel
	sch.reset()
	sch.resetCounters()
}

func TestGenerateKeyPair(t *testing.T) {
	var sknil *[kexPrvSize]byte
	var pknil *[kexPubSize]byte
	if generateKeypair(sknil, pknil) {
		t.Fatal("generateKeypair should fail with nil keys")
	}

	var sk [kexPrvSize]byte
	var pk [kexPubSize]byte

	var buf = &bytes.Buffer{}
	prng = buf
	defer func() {
		prng = rand.Reader
	}()

	if generateKeypair(&sk, &pk) {
		t.Fatal("generateKeypair should fail bad PRNG")
	}

	var p = make([]byte, 48)
	buf.Write(p)
	if generateKeypair(&sk, &pk) {
		t.Fatal("generateKeypair should fail bad PRNG")
	}
}

func TestSigNil(t *testing.T) {
	var signer [IdentityPrivateSize]byte
	var peer [IdentityPublicSize]byte

	if signKEX(nil, &signer) {
		t.Fatal("signKEX should fail with nil kex")
	}

	if verifyKEX(nil, &peer) {
		t.Fatal("verifyKEX should fail with nil kex")
	}
}

func TestDoKEXFail(t *testing.T) {
	sch := &SChannel{}
	if sch.doKEX(nil, nil, false) {
		t.Fatal("doKEX should fail with nil keys")
	}

	var sk = make([]byte, kexPrvSize+1)
	var pk = make([]byte, kexPubSize+1)
	if sch.doKEX(sk[:kexPrvSize-1], pk[:kexPubSize], true) {
		t.Fatal("doKEX should fail with bad key size")
	}

	if sch.doKEX(sk, pk[:kexPubSize], true) {
		t.Fatal("doKEX should fail with bad key size")
	}

	if sch.doKEX(sk[:kexPrvSize], pk, true) {
		t.Fatal("doKEX should fail with bad key size")
	}

	if sch.doKEX(sk[:kexPrvSize], pk[:kexPubSize-1], true) {
		t.Fatal("doKEX should fail with bad key size")
	}
}
