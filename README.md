# sealer

[![Go reference](https://pkg.go.dev/badge/github.com/andreyvit/sealer.svg)](https://pkg.go.dev/github.com/andreyvit/sealer) ![under 350 LOC](https://img.shields.io/badge/size-%3C350%20LOC-green) [![Go Report Card](https://goreportcard.com/badge/github.com/andreyvit/sealer)](https://goreportcard.com/report/github.com/andreyvit/sealer)

Provides io.Writer and io.Reader that transparently compresses and encrypts a stream of data using the modern best practices: zstd and ChaCha20-Poly1305 AEAD with an ephemeral key.

Has only two dependencies:

* [golang.org/x/crypto/chacha20poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)
* [github.com/klauspost/compress/zstd](https://pkg.go.dev/github.com/klauspost/compress/zstd) (has zero dependencies), will be replaced with `compress/zstd` from stdlib [once this accepted Go proposal lands](https://github.com/golang/go/issues/62513).

Sealer is a bit like [filippo.io/age](https://pkg.go.dev/filippo.io/age), but simpler and meant for custom encrypted file formats.

* supports a custom unencrypted file header that comes before the data (the header is authenticated as part of the first encrypted block, so tampering and corruption will be detected);

* single secret encryption key only (with a 32-byte user-definable KeyID so that you can look up the key in your system's keystore).


## Encryption & Compression

Uses modern best practices for cryptography:

* ChaCha20-Poly1305 encryption;

* ephemeral (i.e. per-file) encryption key that is encapsulated by the encryption key;

* encapsulation uses XChaCha20-Poly1305 with a random 192-bit nonce;

* encryption splits the file into chunks (16 KB by default) and uses deterministic nonces for these, marking the final chunk's nonce;

* nothing of the above is configurable.

ChaCha20-Poly1305 has been chosen as a modern and standardized cipher, ensuring wide availability and interoperability. NaCl's XSalsa20-Poly1305 would be similar, but it's standardized so ChaCha20 is a better choice going forward.
AES-256-GCM could also be used here, but ChaCha20 has fewer concerns about complicated attack scenarios.

Before encryption, sealer applies xstd compression, it both provides an excellent time/compression balance, and has an [accepted proposal for inclusion in Go stdlib](https://github.com/golang/go/issues/62513). Until that happens, we use [github.com/klauspost/compress/zstd](https://pkg.go.dev/github.com/klauspost/compress/zstd) which has zero dependencies.


## Usage


### Generating a key

A key is just a `[16]byte` identifier and `[32]byte` secret key:

```go
key := &sealer.Key{}
copy(key.ID[:], "WHATEVER_YA_WANT")

_, err := io.ReadFull(cryptoRand.Reader, key.Key[:])
if err != nil {
	panic(err)
}
````

16 bytes is enough to hold an integer (or two), a UUID, or a short name.


### Sealing

Example:

```go
// prefix is any []byte you want to prepend to the file, can be nil.
w, err := sealer.Seal(&sealed, key, prefix, sealer.SealOptions{})
if err != nil {
	panic(err)
}

for range 100 {
	_, err := w.Write(data)
	if err != nil {
		panic(err)
	}
}

// Very important to close the writer to write the final chunk.
err = w.Close()
if err != nil {
	panic(err)
}
````

If you provide a prefix, `sealer.Seal` will write it to the beginning of the file.


### Opening

```go
o, err := sealer.Prepare(&sealed, prefix)
if err != nil {
	panic(err)
}

key := lookupKey(o.KeyID)

r, err := o.Open(key)
if err != nil {
	panic(err)
}

// Read from r now, for example:
var opened bytes.Buffer
_, err = io.Copy(&opened, r)
if err != nil {
	panic(err)
}
```

Unlike sealer, opener will not read the prefix for you — it assumes you already had to read the file header to make sense of what it is. So if you want a prefix, read it yourself before calling `sealer.Prepare`:

```go
prefix := make([]byte, prefixLen)
_, err := io.ReadFull(&sealed, prefix)
if err != nil {
	panic(err)
}
```


## License

Copyright 2025, Andrey Tarantsov. Distributed under the 2-clause BSD license.
