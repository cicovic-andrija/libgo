package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	AES256IterCount = 250000
	AES256KeyLen    = 32
)

var (
	ErrInvalidData      = errors.New("invalid data on input (empty or unpadded)")
	ErrInvalidPass      = errors.New("invalid passphrase on input (empty)")
	ErrInvalidSalt      = errors.New("invalid salt on input (empty)")
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
)

func EncryptAES256CBCPBKDF2(plaintext []byte, pass string, salt string) ([]byte, error) {
	var (
		block cipher.Block
		err   error
	)

	if len(plaintext) == 0 { // covers the case of plaintext == nil
		return nil, ErrInvalidData
	}
	if pass == "" {
		return nil, ErrInvalidPass
	}
	if salt == "" {
		return nil, ErrInvalidSalt
	}

	if block, err = aes.NewCipher(
		pbkdf2.Key(
			[]byte(pass),
			[]byte(salt),
			AES256IterCount,
			AES256KeyLen,
			sha256.New,
		),
	); err != nil {
		return nil, ErrEncryptionFailed
	}

	input, err := PadPKCS7(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, ErrEncryptionFailed
	}

	ciphertext := make([]byte, len(iv)+len(input)) // multiple of aes.BlockSize
	copy(ciphertext, iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext[aes.BlockSize:], input)

	return ciphertext, nil
}

func DecryptAES256CBCPBKDF2(ciphertext []byte, pass string, salt string) ([]byte, error) {
	var (
		block cipher.Block
		err   error
	)

	if len(ciphertext) == 0 { // covers the case of ciphertext == nil
		return nil, ErrInvalidData
	}
	if pass == "" {
		return nil, ErrInvalidPass
	}
	if salt == "" {
		return nil, ErrInvalidSalt
	}

	if len(ciphertext)%aes.BlockSize != 0 || len(ciphertext)/aes.BlockSize < 2 { // first block must be taken as iv
		return nil, ErrInvalidData
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if block, err = aes.NewCipher(
		pbkdf2.Key(
			[]byte(pass),
			[]byte(salt),
			AES256IterCount,
			AES256KeyLen,
			sha256.New,
		),
	); err != nil {
		return nil, ErrDecryptionFailed
	}

	plaintext := make([]byte, len(ciphertext)) // multiple of aes.BlockSize
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	if plaintext, err = UnpadPKCS7(plaintext, aes.BlockSize); err != nil {
		return nil, err
	}
	return plaintext, nil
}
