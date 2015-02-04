package schannel

import "testing"

func verifyZeroised(in []byte, t *testing.T) {
	for i := 0; i < len(in); i++ {
		if in[i] != 0 {
			t.Fatal("buffer was not zeroised")
		}
	}
}

func verifyNotZeroised(in []byte, t *testing.T) {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			t.Fatal("buffer was zeroised but shouldn't be")
		}
	}
}

func newBuffer(n int) []byte {
	p := make([]byte, n)
	for i := 0; i < n; i++ {
		b := byte(n % 255)
		if b == 0 {
			b = 1
		}
		p[i] = b
	}

	return p
}

func TestZero(t *testing.T) {
	zero(nil, 32)

	p := newBuffer(32)
	zero(p, 0)
	verifyZeroised(p, t)

	p = newBuffer(64)
	zero(p, 0)
	verifyZeroised(p, t)

	p = newBuffer(32)
	zero(p, 10)
	verifyZeroised(p[:10], t)
	verifyNotZeroised(p[10:], t)
}
