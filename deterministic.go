package rip

import (
	"crypto/aes"
	"crypto/cipher"
	"net/netip"
)

type DeterministicEncryption struct {
	block cipher.Block
}

func NewDeterministicEncryption(k Key) (*DeterministicEncryption, error) {
	if k.Len() != KeySize128 {
		return nil, ErrKeySize
	}

	block, err := aes.NewCipher(k.bytes())

	if err != nil {
		return nil, ErrKeySize
	}

	return &DeterministicEncryption{block: block}, nil
}

func (d *DeterministicEncryption) Encrypt(addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, ErrInvalidIPAddress
	}

	in := addr.As16()

	var out [16]byte

	d.block.Encrypt(out[:], in[:])

	return netip.AddrFrom16(out).Unmap(), nil
}

func (d *DeterministicEncryption) Decrypt(addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, ErrInvalidIPAddress
	}

	in := addr.As16()

	var out [16]byte

	d.block.Decrypt(out[:], in[:])

	return netip.AddrFrom16(out).Unmap(), nil
}
