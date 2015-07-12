# go-schannel

This is an interoperable Go implementation of
[libschannel](https://github.com/kisom/libschannel). It is intended
for small embedded systems (and their counterpart server programs) for
which a full-fledged PKI is unnecessary; most people will want to use
a mutally-authenticated TLS-secured TCP connection.

GoDoc: [go-schannel](https://godoc.org/github.com/kisom/go-schannel/schannel)

It provides bi-directional secure channels over an insecure communications
channel (in this case, a Go `io.ReadWriter`).


## LICENSE

This program is dual licensed. You may choose either the public domain
license or the ISC license; the intent is to provide maximum freedom of
use to the end user.
