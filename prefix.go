package rip

import (
	"encoding/binary"
	"net/netip"
)

type block128 struct {
	w0 uint64
	w1 uint64
}

func newBlock128(b [16]byte) block128 {
	return block128{
		w0: binary.BigEndian.Uint64(b[0:8]),
		w1: binary.BigEndian.Uint64(b[8:16]),
	}
}

func (b block128) store(dst *[16]byte) {
	binary.BigEndian.PutUint64(dst[0:8], b.w0)
	binary.BigEndian.PutUint64(dst[8:16], b.w1)
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
	}

	b.w0 |= v << (pos - 64)
}

func (b block128) shiftLeftBy1() block128 {
	return block128{w0: b.w0<<1 | b.w1>>63, w1: b.w1 << 1}
}

func (b block128) isV4() bool {
	return b.w0 == 0 && b.w1>>32 == 0xFFFF
}

func (b block128) address() netip.Addr {
	var raw [16]byte

	b.store(&raw)

	a := netip.AddrFrom16(raw)

	if b.isV4() {
		return a.Unmap()
	}

	return a
}
