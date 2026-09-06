package rip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"net/netip"
)

const TokenSize = 16

const AddrSize = 16

type Token [TokenSize]byte

type Pseudo struct {
	k1, k2 cipher.Block
}

func NewPseudo(k Key) (*Pseudo, error) {
	if k.Len() != KeySize256 {
		return nil, ErrKeySize
	}

	raw := k.bytes()

	if subtle.ConstantTimeCompare(raw[:KeySize128], raw[KeySize128:]) == 1 {
		return nil, ErrKeyHalvesEqual
	}

	k1, err := aes.NewCipher(raw[:KeySize128])

	if err != nil {
		return nil, ErrKeySize
	}

	k2, err := aes.NewCipher(raw[KeySize128:])

	if err != nil {
		return nil, ErrKeySize
	}

	return &Pseudo{k1: k1, k2: k2}, nil
}

func (p *Pseudo) Token(addr netip.Addr) (Token, error) {
	return p.TokenFromScratch(new(ScratchToken), addr)
}

// use it directly to avoid heap allocation
func (p *Pseudo) TokenFromScratch(s *ScratchToken, addr netip.Addr) (Token, error) {
	if !addr.IsValid() {
		return Token{}, ErrInvalidIPAddress
	}

	s.ip = addr.As16()

	p.k1.Encrypt(s.e1[:], s.ip[:])
	p.k2.Encrypt(s.e2[:], s.ip[:])

	for i := range s.e1 {
		s.e1[i] ^= s.e2[i]
	}

	return s.e1, nil
}

type ScratchToken struct {
	ip     [AddrSize]byte
	e1, e2 [TokenSize]byte
}

func (s *ScratchToken) Zero() { *s = ScratchToken{} }

func TokensEqual(a, b Token) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
