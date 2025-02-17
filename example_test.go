package sealer_test

import (
	"bytes"
	cryptoRand "crypto/rand"
	"fmt"
	"io"

	"github.com/andreyvit/sealer"
)

func Example() {
	const prefixLen = 32

	prefix := make([]byte, prefixLen)
	copy(prefix, "MY_DATA_FORMAT_HEADER_GOES_HERE!")

	key := &sealer.Key{}
	copy(key.ID[:], "WHATEVER_YA_WANT")
	_, err := io.ReadFull(cryptoRand.Reader, key.Key[:])
	if err != nil {
		panic(err)
	}

	// generate non-random compressible data to demonstrate compression
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	var sealed bytes.Buffer
	var expectedData bytes.Buffer
	{ // Sealing
		w, err := sealer.Seal(&sealed, key, prefix, sealer.SealOptions{})
		if err != nil {
			panic(err)
		}

		var totalUncompressedSize int
		for range 100 {
			_, err := w.Write(data)
			if err != nil {
				panic(err)
			}

			totalUncompressedSize += len(data)
			expectedData.Write(data)
		}

		// Very important to close the writer to write the final chunk.
		err = w.Close()
		if err != nil {
			panic(err)
		}

		fmt.Printf("%d bytes input => %d bytes sealed\n", totalUncompressedSize, sealed.Len())
	}

	{ // Opening
		fmt.Printf("Preparing to open:\n")
		actualPrefix := make([]byte, prefixLen)
		_, err := io.ReadFull(&sealed, actualPrefix)
		if err != nil {
			panic(err)
		}
		fmt.Printf("prefix = %s\n", actualPrefix)

		o, err := sealer.Prepare(&sealed, actualPrefix)
		if err != nil {
			panic(err)
		}
		fmt.Printf("key ID = %s\n", o.KeyID[:])

		r, err := o.Open(key)
		if err != nil {
			panic(err)
		}

		var opened bytes.Buffer
		_, err = io.Copy(&opened, r)
		if err != nil {
			panic(err)
		}

		if !bytes.Equal(opened.Bytes(), expectedData.Bytes()) {
			fmt.Println("data mismatch!")
		}
	}

	// Output: 20000 bytes input => 369 bytes sealed
	// Preparing to open:
	// prefix = MY_DATA_FORMAT_HEADER_GOES_HERE!
	// key ID = WHATEVER_YA_WANT
}
