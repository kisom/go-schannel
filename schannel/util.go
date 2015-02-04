package schannel

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
