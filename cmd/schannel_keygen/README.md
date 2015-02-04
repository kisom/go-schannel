# schannel_keygen
## generate schannel identity keypairs

This is a Go implementation of the `schannel_keygen` program that ships with
libschannel. It is designed to be a simple tool for producing keypairs that
can be used with schannel.

## Usage

```
schannel_keygen basenames...
```
This program will output a pair of files for each basename:

* basename.key: private signature (identity key)
* basename.pub: public signature (identity key)

These files will be in the binary form that can be directly loaded into
the `schannel_dial` and `schannel_listen` functions.


