package rip

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrInvalidIPBits = errors.New("rip: invalid IP bits")
	ErrInvalidIP     = errors.New("rip: invalid IP")
)

const (
	DefaultIPv4Bits = 16
	DefaultIPv6Bits = 48
)

type Mask struct {
	ipv4Bits int
	ipv6Bits int
}

func (m *Mask) Hide(ip netip.Addr) (netip.Addr, error) {
	ip = ip.Unmap()

	if !ip.IsValid() {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}

	bits := m.ipv4Bits

	if ip.Is6() {
		bits = m.ipv6Bits
	}

	p, err := ip.Prefix(bits)

	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %d", ErrInvalidIPBits, bits)
	}

	return p.Addr(), nil
}

func DefaultMask() *Mask {
	return &Mask{
		ipv4Bits: DefaultIPv4Bits,
		ipv6Bits: DefaultIPv6Bits,
	}
}

func NewMask(ipv4Bits, ipv6Bits int) (*Mask, error) {
	if ipv4Bits < 0 || ipv4Bits > 32 {
		return nil, fmt.Errorf("%w for IPv4: got %d, expected 0-32", ErrInvalidIPBits, ipv4Bits)
	}

	if ipv6Bits < 0 || ipv6Bits > 128 {
		return nil, fmt.Errorf("%w for IPv6: got %d, expected 0-128", ErrInvalidIPBits, ipv6Bits)
	}

	return &Mask{
		ipv4Bits: ipv4Bits,
		ipv6Bits: ipv6Bits,
	}, nil
}
