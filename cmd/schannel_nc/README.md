# schannel_nc
## A netcat-like program that communicates over secure channels.

This is a Go implementation of the `schannel_nc` program that ships with
libschannel. It is designed to be a simple example of using the schannel
package, and to facilitate some basic use tests of the code.

## Usage

There are two way to use `schannel_nc`: as a client program that sends data
to a server, or as a server program that receives data from a client.

### Client
```
schannel_nc  [-hk] [-s signer] [-v verifier] host port
```

### Server
```
schannel_nc [-hkl] [-s signer] [-v verifier] port
```

### Flags
The following flags are defined:
* `-h`: print a short usage message and exit
* `-k`: force the program to keep listening after the client
  disconnects. This must be used with -l.
* `-l`: listen for an incoming connection
* `-s signer`: specify the path to a signature key
* `-v verifier`: specify the path to a verification key

If a signature key is specified, it will be used to sign the key exchange. If a
verification key is specified, it will be used to verify the signature on the
key exchange.


## License

This program is dual licensed. You may choose either the public domain
license or the ISC license; the intent is to provide maximum freedom of
use to the end user.

