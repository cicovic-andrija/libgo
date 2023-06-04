package crypto

import (
	"bytes"
	"errors"
)

var (
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
	ErrInvalidBlockSize    = errors.New("invalid block size")
)

func PadPKCS7(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}

	if len(b) == 0 { // covers the case of b == nil
		return nil, ErrInvalidData
	}

	n := blockSize - (len(b) % blockSize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func UnpadPKCS7(b []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, ErrInvalidBlockSize
	}

	if len(b) == 0 { // covers the case of b == nil
		return nil, ErrInvalidData
	}

	n := int(b[len(b)-1])

	if len(b)%blockSize != 0 || n == 0 || n > blockSize {
		return nil, ErrInvalidPKCS7Padding
	}

	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != b[len(b)-1] {
			return nil, ErrInvalidPKCS7Padding
		}
	}

	return b[:len(b)-n], nil
}
