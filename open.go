package sealer

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

// Prepare read a sealed file header and prepares to open it. Crucially,
// the Openable returned contains a KeyID which you can use to decide
// which key to provide to the Open method.
func Prepare(in io.Reader, outerPrefix []byte) (*Openable, error) {
	oplen := len(outerPrefix)
	prefix := make([]byte, oplen+headerSize)
	copy(prefix, outerPrefix)
	header := prefix[oplen:]

	if _, err := io.ReadFull(in, header); err != nil {
		return nil, err
	}

	version := int(binary.LittleEndian.Uint32(header[offVersion : offVersion+4]))
	chunkSize := int(binary.LittleEndian.Uint32(header[offChunkSize : offChunkSize+4]))

	if version != 0 {
		return nil, ErrUnsupportedVersion
	}
	if chunkSize == 0 || chunkSize > MaxChunkSize {
		return nil, ErrChunkSizeTooLarge
	}

	opn := &Openable{
		in:        in,
		prefix:    prefix,
		chunkSize: chunkSize,
	}
	copy(opn.KeyID[:], header[offKeyID:offKeyID+IDSize])
	copy(opn.encapsulated[:], header[offEncKey:headerSize])

	return opn, nil
}

type Openable struct {
	KeyID        [IDSize]byte
	in           io.Reader
	prefix       []byte
	chunkSize    int
	encapsulated [nonceSizeX + KeySize + overhead]byte
}

func (opn *Openable) Open(key *Key) (*Reader, error) {
	var ephemeralKey [KeySize]byte
	err := decapsulate(ephemeralKey[:], key.Key[:], opn.encapsulated[:])
	if err != nil {
		return nil, err
	}
	// log.Printf("dec: ephemeral key = [%s] %x", hash(ephemeralKey[:]), ephemeralKey[:])

	aead, err := chacha20poly1305.New(ephemeralKey[:])
	if err != nil {
		panic(err)
	}

	r := &Reader{
		dec: decryptor{
			in:        opn.in,
			chunkSize: opn.chunkSize,
			readBuf:   make([]byte, chunkHeaderSize+opn.chunkSize+overhead),
			decBuf:    make([]byte, opn.chunkSize),
			aead:      aead,
		},
	}

	err = r.dec.read(opn.prefix)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt the first chunk: %w", err)
	}

	r.decompr, err = zstd.NewReader(&r.dec, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}

	return r, nil
}

type Reader struct {
	decompr *zstd.Decoder
	dec     decryptor
}

func (r *Reader) Read(p []byte) (n int, err error) {
	return r.decompr.Read(p)
}

type decryptor struct {
	in         io.Reader
	chunkSize  int
	readBuf    []byte
	decBuf     []byte
	buf        []byte
	chunkIndex uint32
	aead       cipher.AEAD
	eof        bool
}

func (dec *decryptor) Read(p []byte) (n int, err error) {
	if len(dec.buf) == 0 {
		err = dec.read(nil)
		if err != nil {
			return 0, err
		}
	}
	n = min(len(p), len(dec.buf))
	copy(p, dec.buf[:n])
	dec.buf = dec.buf[n:]
	err = nil
	return
}

func (dec *decryptor) read(prefix []byte) error {
	if dec.eof {
		return io.EOF
	}
	n, err := io.ReadFull(dec.in, dec.readBuf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}
	if err != nil {
		return err
	}
	if n < chunkHeaderSize+overhead {
		return io.ErrUnexpectedEOF
	}

	headerIndex := binary.LittleEndian.Uint32(dec.readBuf[:chunkHeaderSize])
	isFinal := (headerIndex == finalChunkIndex)
	if !isFinal && headerIndex != dec.chunkIndex {
		return fmt.Errorf("data corruption: wanted chunk %d, got %d", dec.chunkIndex, headerIndex)
	}

	var nonce [nonceSizeS]byte
	fillNonce(&nonce, dec.chunkIndex, isFinal)
	dec.chunkIndex++

	sealed := dec.readBuf[chunkHeaderSize:n]

	// log.Printf("dec: headerIndex = %d, prefix = %d [%s], nonce = %x", headerIndex, len(prefix), hash(prefix), nonce[:])
	// log.Printf("dec: sealed = %d [%s]: %x", len(sealed), hash(sealed), sealed)

	buf, err := dec.aead.Open(dec.decBuf[:0], nonce[:], sealed, prefix)
	if err != nil {
		return err
	}
	dec.buf = buf
	dec.eof = isFinal
	return nil
}

func decapsulate(output []byte, key []byte, encapsulated []byte) error {
	ea, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}

	// log.Printf("decapsulate: sealed = [%s]: %x", hash(encapsulated[:]), encapsulated[:])
	// log.Printf("decapsulate: pre-key = [%s]: %x", hash(encapsulated[nonceSizeX:nonceSizeX+KeySize]), encapsulated[nonceSizeX:nonceSizeX+KeySize])

	_, err = ea.Open(output[:0], encapsulated[:nonceSizeX], encapsulated[nonceSizeX:nonceSizeX+KeySize+overhead], nil)

	// log.Printf("decapsulate: nonce = [%s]: %x", hash(encapsulated[:nonceSizeX]), encapsulated[:nonceSizeX])
	// log.Printf("decapsulate: key = [%s]: %x", hash(output), output)
	return err
}

func hash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
