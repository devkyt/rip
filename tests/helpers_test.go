package rip_test

import (
	"math/bits"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

var (
	testSecret = []byte("rip-test-master-secret-0123456789")
	testSalt   = []byte("rip-test-salt")
)

func masterKey(t *testing.T) *rip.MasterKey {
	t.Helper()

	mk, err := rip.NewMasterKey(testSecret, testSalt)

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	return mk
}

func deriveKey(t *testing.T, mode rip.Mode, size int) rip.Key {
	t.Helper()

	k, err := masterKey(t).Derive(mode, size)

	if err != nil {
		t.Fatalf("Derive(%q, %d): %v", mode, size, err)
	}

	return k
}

func commonPrefixLen(t *testing.T, a, b netip.Addr) int {
	t.Helper()

	if a.Is4() != b.Is4() {
		t.Fatalf("commonPrefixLen: mismatched families %s / %s", a, b)
	}

	var x, y []byte

	if a.Is4() {
		xa, ya := a.As4(), b.As4()
		x, y = xa[:], ya[:]
	} else {
		xa, ya := a.As16(), b.As16()
		x, y = xa[:], ya[:]
	}

	n := 0

	for i := range x {
		d := x[i] ^ y[i]

		if d == 0 {
			n += 8

			continue
		}

		n += bits.LeadingZeros8(d)

		break
	}

	return n
}
