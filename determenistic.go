package rip

import (
	"crypto/aes"
	"crypto/cipher"
)

type DetermenisticEncryption struct {
	block cipher.Block
}

func NewDetermenisticEncryption(k Key) (*DetermenisticEncryption, error) {
	if k.Len() != KeySize128 {
		return nil, ErrKeySize
	}

	block, err := aes.NewCipher(k.bytes())

	if err != nil {
		return nil, err
	}

	return &DetermenisticEncryption{block: block}, nil
}
