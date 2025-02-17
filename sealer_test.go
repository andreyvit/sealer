package sealer_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/andreyvit/sealer"
)

func TestSealer_simple(t *testing.T) {
	run(t, 8, 3, 1, 7)
}

func TestSealer_large(t *testing.T) {
	chunkSizes := []int{1, 2, 3, 8, 32, 1000, 16 * 1024}
	multiples := []int{0, 1, 10, 128}
	remainders := []int{-2, -1, 0, 1, 2}
	writeSizes := []int{0, 1, 2, 8, 1024}

	for _, chunkSize := range chunkSizes {
		for _, multiple := range multiples {
			for _, remainder := range remainders {
				dataSize := multiple*int(chunkSize) + remainder
				if dataSize < 0 {
					continue
				}

				var plusMinusRemainder string
				if remainder > 0 {
					plusMinusRemainder = fmt.Sprintf("_plus_%d", remainder)
				} else if remainder < 0 {
					plusMinusRemainder = fmt.Sprintf("_minus_%d", -remainder)
				}

				for _, writeSize := range writeSizes {
					if writeSize == 0 {
						writeSize = int(chunkSize)
						if slices.Contains(writeSizes, writeSize) {
							continue
						}
					}

					name := fmt.Sprintf("%dx%d%s_in_%d", multiple, chunkSize, plusMinusRemainder, writeSize)
					t.Run(name, func(t *testing.T) {
						if dataSize >= 1024*1024 && testing.Short() {
							t.Skip("skipped - too big")
							return
						}
						run(t, chunkSize, multiple, remainder, writeSize)
					})
				}
			}
		}
	}
}

func run(t *testing.T, chunkSize, multiple, remainder, writeSize int) {
	key := generateKey()

	var originalPrefix [32]byte
	copy(originalPrefix[:], "12345678901234567890123456789012")

	dataSize := multiple*int(chunkSize) + remainder
	original := make([]byte, dataSize)
	if _, err := io.ReadFull(rand.Reader, original); err != nil {
		t.Fatal(err)
	}

	input := slices.Clone(original)
	var sealedBuf bytes.Buffer
	w, err := sealer.Seal(&sealedBuf, key, originalPrefix[:], sealer.SealOptions{ChunkSize: chunkSize})
	if err != nil {
		t.Fatal(err)
	}
	for len(input) > 0 {
		ws := min(len(input), writeSize)
		_, err := w.Write(input[:ws])
		if err != nil {
			t.Fatal(err)
		}
		input = input[ws:]
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	in := bytes.NewReader(sealedBuf.Bytes())

	var actualPrefix [32]byte
	_, err = io.ReadFull(in, actualPrefix[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualPrefix[:], originalPrefix[:]) {
		t.Fatalf("got prefix %x, expected %x", actualPrefix[:], originalPrefix[:])
	}

	opn, err := sealer.Prepare(in, originalPrefix[:])
	if err != nil {
		t.Fatal(err)
	}

	if opn.KeyID != key.ID {
		t.Fatalf("expected key ID %x, got %x", key.ID, opn.KeyID)
	}
	r, err := opn.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, actual) {
		t.Fatalf("got:\n%x\n\nwanted:\n%x", actual, original)
	}
}

func generateKey() *sealer.Key {
	key := &sealer.Key{}
	copy(key.ID[:], "EXAMPLE")
	if _, err := io.ReadFull(rand.Reader, key.Key[:]); err != nil {
		panic(err)
	}
	return key
}
