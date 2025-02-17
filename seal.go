package sealer

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

func Seal(out io.Writer, key *Key, outerPrefix []byte, opt SealOptions) (*Writer, error) {
	if opt.ChunkSize == 0 {
		opt.ChunkSize = DefaultChunkSize
	}
	if opt.RandomReader == nil {
		opt.RandomReader = rand.Reader
	}

	var encapsulated [nonceSizeX + KeySize + overhead]byte

	_, err := io.ReadFull(opt.RandomReader, encapsulated[:nonceSizeX+KeySize])
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	aead, err := chacha20poly1305.New(encapsulated[nonceSizeX : nonceSizeX+KeySize])
	if err != nil {
		panic(err)
	}
	// log.Printf("enc: ephemeral key = [%s] %x", hash(encapsulated[nonceSizeX:nonceSizeX+KeySize]), encapsulated[nonceSizeX:nonceSizeX+KeySize])

	// after this call, plaintext key is no longer on the stack (just in case)
	encapsulate(key.Key[:], encapsulated[:])

	prefix := make([]byte, 0, len(outerPrefix)+envelopeHeaderSize)
	prefix = append(prefix, outerPrefix...)
	prefix = binary.LittleEndian.AppendUint32(prefix, opt.ChunkSize)
	prefix = append(prefix, key.ID[:]...)
	prefix = append(prefix, encapsulated[:]...)

	w := &Writer{
		enc: encryptor{
			out:       out,
			chunkSize: int(opt.ChunkSize),
			buf:       make([]byte, 0, 2*opt.ChunkSize),
			outputBuf: make([]byte, chunkHeaderSize+opt.ChunkSize+overhead),
			prefix:    prefix,
			aead:      aead,
		},
	}

	w.compr, err = zstd.NewWriter(&w.enc)
	if err != nil {
		panic(err)
	}

	return w, nil
}

type Writer struct {
	enc   encryptor
	compr *zstd.Encoder
}

func (w *Writer) Write(data []byte) (int, error) {
	return w.compr.Write(data)
}

func (w *Writer) Close() error {
	err := w.compr.Close()
	if err != nil {
		return err
	}
	return w.enc.Close()
}

type encryptor struct {
	out        io.Writer
	chunkSize  int
	prefix     []byte
	buf        []byte
	outputBuf  []byte
	chunkIndex uint32
	aead       cipher.AEAD
}

func (w *encryptor) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	buf := append(w.buf, data...)
	n := len(buf)
	cs := w.chunkSize
	if n > cs {
		start := 0
		for start+cs < n {
			// log.Printf("enc: flushing: start = %d, cs = %d, n = %d", start, cs, n)
			err := w.flush(buf[start:start+cs], false)
			if err != nil {
				return 0, err
			}
			start += cs
		}
		rem := n - start
		// log.Printf("enc: after flush: start = %d, n = %d, rem = %d", start, n, rem)
		if start > 0 {
			copy(buf, buf[start:])
		}
		buf = buf[:rem]
		// log.Printf("enc: final after flush: len(buf) = %d", len(buf))
	}
	w.buf = buf

	return len(data), nil
}

func (w *encryptor) Close() error {
	err := w.flush(w.buf, true)
	if err != nil {
		return err
	}
	return nil
}

func (e *encryptor) flush(buf []byte, isFinal bool) error {
	if e.prefix != nil {
		_, err := e.out.Write(e.prefix)
		if err != nil {
			return err
		}
	}

	headerIndex := e.chunkIndex
	if isFinal {
		headerIndex = finalChunkIndex
	}

	var nonce [nonceSizeS]byte
	fillNonce(&nonce, e.chunkIndex, isFinal)
	e.chunkIndex++

	// log.Printf("enc: headerIndex = %d, prefix = %d [%s], nonce = %x, buf = %d [%s]: %x", headerIndex, len(e.prefix), hash(e.prefix), nonce[:], len(buf), hash(buf), buf)

	sealed := e.aead.Seal(e.outputBuf[chunkHeaderSize:chunkHeaderSize], nonce[:], buf, e.prefix)
	// log.Printf("enc: sealed = %d [%s]: %x", len(sealed), hash(sealed), sealed)
	output := e.outputBuf[:chunkHeaderSize+len(sealed)]
	e.prefix = nil

	binary.LittleEndian.PutUint32(output[:chunkHeaderSize], headerIndex)

	_, err := e.out.Write(output)
	return err
}

func encapsulate(key []byte, encapsulated []byte) {
	ea, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}

	// log.Printf("encapsulate: nonce = [%s]: %x", hash(encapsulated[:nonceSizeX]), encapsulated[:nonceSizeX])
	// log.Printf("encapsulate: key = [%s]: %x", hash(encapsulated[nonceSizeX:nonceSizeX+KeySize]), encapsulated[nonceSizeX:nonceSizeX+KeySize])

	ea.Seal(encapsulated[nonceSizeX:nonceSizeX], encapsulated[:nonceSizeX], encapsulated[nonceSizeX:nonceSizeX+KeySize], nil)
	// log.Printf("encapsulate: sealed = [%s]: %x", hash(encapsulated[:]), encapsulated[:])
}
