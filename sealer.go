// Package sealer provides transparent compression and encryption of data.
package sealer

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize    = chacha20poly1305.KeySize
	IDSize     = 16
	nonceSizeS = chacha20poly1305.NonceSize
	nonceSizeX = chacha20poly1305.NonceSizeX
	overhead   = chacha20poly1305.Overhead
)

type Key struct {
	ID  [16]byte
	Key [KeySize]byte
}

type SealOptions struct {
	ChunkSize    uint32
	RandomReader io.Reader
}

const DefaultChunkSize uint32 = 32 * 1024

// envelope -> header recipients* (chunk_off_1 ... chunk_off_{n+1})

type envelopeHeader struct {
	ChunkSize                uint32
	AccessKeyID              [16]byte
	EncapsulatedEphemeralKey [nonceSizeX + KeySize + overhead]byte
}

const envelopeHeaderSize = 4 + IDSize + nonceSizeX + KeySize + overhead

const chunkHeaderSize = 4

const finalChunkIndex uint32 = 0xffff_ffff

func fillNonce(nonce *[nonceSizeS]byte, i uint32, isFinal bool) {
	binary.LittleEndian.PutUint32(nonce[:4], i)
	if isFinal {
		nonce[nonceSizeS-1] = 1
	}
}
