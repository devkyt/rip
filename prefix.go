package rip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"net/netip"
)

const (
	pfxBatch  = 8
	v4TopBits = 0x0000FFFF
)

var (
	padPfx0  = block128{w0: 0, w1: 1}
	padPfx96 = block128{w0: 1 << 32, w1: 0xFFFF}
)

type ScratchPrefix struct {
	in  [pfxBatch][16]byte
	out [2 * pfxBatch][16]byte
}

type Prefix struct {
	k1, k2 cipher.Block
}

func NewPrefix(k Key) (*Prefix, error) {
	if k.Len() != KeySize256 {
		return nil, ErrKeySize
	}

	raw := k.bytes()

	if subtle.ConstantTimeCompare(raw[:16], raw[16:]) == 1 {
		return nil, ErrKeyHalvesEqual
	}

	k1, err := aes.NewCipher(raw[:16])

	if err != nil {
		return nil, ErrKeySize
	}

	k2, err := aes.NewCipher(raw[16:])

	if err != nil {
		return nil, ErrKeySize
	}

	return &Prefix{k1: k1, k2: k2}, nil
}

func (p *Prefix) Encrypt(addr netip.Addr) (netip.Addr, error) {
	var s ScratchPrefix

	return p.EncryptScratch(&s, addr)
}

func (p *Prefix) EncryptScratch(s *ScratchPrefix, addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, ErrInvalidIPAddress
	}

	return p.encrypt(s, newBlock128(addr.As16())), nil
}

func (p *Prefix) encrypt(s *ScratchPrefix, in block128) netip.Addr {
	start, pp, out := begin(in)

	for n := start; n < 128; n += pfxBatch {
		for i := range pfxBatch {
			pp.to(&s.in[i])
			pp.shiftLeftBy1()
			pp.setBit(0, in.bit(127-(n+uint(i))))
		}

		for i := range pfxBatch {
			p.k1.Encrypt(s.out[2*i][:], s.in[i][:])
			p.k2.Encrypt(s.out[2*i+1][:], s.in[i][:])
		}

		for i := range pfxBatch {
			pos := 127 - (n + uint(i))
			cb := uint64(s.out[2*i][15]^s.out[2*i+1][15]) & 1

			out.setBit(pos, in.bit(pos)^cb)
		}
	}

	return out.address()
}

func (p *Prefix) Decrypt(addr netip.Addr) (netip.Addr, error) {
	var s ScratchPrefix

	return p.DecryptScratch(&s, addr)
}

func (p *Prefix) DecryptScratch(s *ScratchPrefix, addr netip.Addr) (netip.Addr, error) {
	if !addr.IsValid() {
		return netip.Addr{}, ErrInvalidIPAddress
	}

	return p.decrypt(s, newBlock128(addr.As16())), nil
}

func (p *Prefix) decrypt(s *ScratchPrefix, in block128) netip.Addr {
	start, pp, out := begin(in)

	for n := start; n < 128; n++ {
		cb := p.pfxBit(s, pp)

		pos := 127 - n

		pb := in.bit(pos) ^ cb

		out.setBit(pos, pb)

		pp = pp.shiftLeftBy1()

		pp.setBit(0, pb)
	}

	return out.address()
}

func (p *Prefix) pfxBit(s *ScratchPrefix, pp block128) uint64 {
	pp.to(&s.in[0])

	p.k1.Encrypt(s.out[0][:], s.in[0][:])
	p.k2.Encrypt(s.out[1][:], s.in[0][:])

	return uint64(s.out[0][15]^s.out[1][15]) & 1
}

func begin(in block128) (start uint, pp block128, out block128) {
	if in.isV4() {
		out.w1 = v4TopBits << 32

		return 96, padPfx96, out
	}

	return 0, padPfx0, out
}

type block128 struct {
	w0, w1 uint64
}

func newBlock128(b [16]byte) block128 {
	return block128{
		w0: binary.BigEndian.Uint64(b[0:8]),
		w1: binary.BigEndian.Uint64(b[8:16]),
	}
}

func (b block128) bit(pos uint) uint64 {
	if pos < 64 {
		return b.w1 >> pos & 1
	}

	return b.w0 >> (pos - 64) & 1
}

func (b block128) setBit(pos uint, v uint64) {
	if pos < 64 {
		b.w1 |= v << pos

		return
	}

	b.w0 |= v << (pos - 64)
}

func (b block128) shiftLeftBy1() block128 {
	return block128{w0: b.w0<<1 | b.w1>>63, w1: b.w1 << 1}
}

func (b block128) address() netip.Addr {
	var raw [16]byte

	b.to(&raw)

	a := netip.AddrFrom16(raw)

	if b.isV4() {
		return a.Unmap()
	}

	return a
}

func (b block128) to(dst *[16]byte) {
	binary.BigEndian.PutUint64(dst[0:8], b.w0)
	binary.BigEndian.PutUint64(dst[8:16], b.w1)
}

func (b block128) isV4() bool {
	return b.w0 == 0 && b.w1>>32 == v4TopBits
}
