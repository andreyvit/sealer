// Package sealer provides transparent compression and encryption of data.
package sealer

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the length of Cacha20-Poly1305 key (32 bytes).
	KeySize = chacha20poly1305.KeySize

	// IDSize is the length of a user-defined key ID used by this package
	// (32 bytes).
	IDSize = 32

	nonceSizeS = chacha20poly1305.NonceSize
	nonceSizeX = chacha20poly1305.NonceSizeX
	overhead   = chacha20poly1305.Overhead
)

// Key is a user-provided encrypted key. It is used once per sealing operation,
// to encapsulate (i.e. encrypt) an ephemeral file key. You can generate the key
// bytes by reading from crypto/rand.Reader. NIST recommends that you limit
// using a single key to no more than 2^32 Seal operations.
type Key struct {
	ID  [IDSize]byte
	Key [KeySize]byte
}

type SealOptions struct {
	ChunkSize    int
	ZstdLevel    int
	RandomReader io.Reader
}

// DefaultChunkSize is the default value of SealOptions.ChunkSize used by
// the sealer.
const DefaultChunkSize int = 32 * 1024

// MaxChunkSize is the maximum value of SealOptions.ChunkSize that can be
// used by the sealer, and the maximum size that opener will accept,
// in order to avoid DoS attacks when reading untrusted files.
const MaxChunkSize int = 1024 * 1024

var (
	ErrChunkSizeTooLarge  = errors.New("chunk size too large")
	ErrUnsupportedVersion = errors.New("unsupported or corrupted sealed file")
)

// Envelope header format:
//  - version         uint32 (zero so far, for version and/or multiple keys)
//  - chunkSize       uint32
//  - accessKeyID     [IDSize]byte
//  - encapsulatedKey [nonceSizeX + KeySize + overhead]byte

const (
	headerSize   = 8 + IDSize + nonceSizeX + KeySize + overhead
	offVersion   = 0
	offChunkSize = offVersion + 4
	offKeyID     = offChunkSize + 4
	offEncKey    = offKeyID + IDSize
)

const chunkHeaderSize = 4

const finalChunkIndex uint32 = 0xffff_ffff

func fillNonce(nonce *[nonceSizeS]byte, i uint32, isFinal bool) {
	binary.LittleEndian.PutUint32(nonce[:4], i)
	if isFinal {
		nonce[nonceSizeS-1] = 1
	}
}
