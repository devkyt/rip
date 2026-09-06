package rip_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

func Test_NewDeterministicEncryption_Error_When_Wrong_Key_Size(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize256)

	if _, err := rip.NewDeterministicEncryption(k); !errors.Is(err, rip.ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func Test_DeterministicEncryption_Round_Trip(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	d, err := rip.NewDeterministicEncryption(k)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	ips := []string{
		"0.0.0.0",
		"192.0.2.1",
		"255.255.255.255",
		"::",
		"2001:db8::1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}

	for _, s := range ips {
		ip := netip.MustParseAddr(s)

		enc, err := d.Encrypt(ip)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", s, err)
		}

		dec, err := d.Decrypt(enc)

		if err != nil {
			t.Fatalf("Decrypt %s: %v", s, err)
		}

		if dec != ip {
			t.Fatalf("round trip %s: got %s, want %s", s, dec, ip)
		}
	}
}

func Test_DeterministicEncryption_Is_Deterministic(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	d, err := rip.NewDeterministicEncryption(k)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	a, err := d.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	b, err := d.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if a != b {
		t.Fatalf("non-determenistic output: %s != %s", a, b)
	}
}

func Test_DeterministicEncryption_Changes_Address(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	d, err := rip.NewDeterministicEncryption(k)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	enc, err := d.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if enc == ip {
		t.Fatalf("Encrypt left address unchanged: %s", enc)
	}
}

func Test_DeterministicEncryption_Distinct_Keys_Produce_Distinct_Output(t *testing.T) {
	mk1, err := rip.NewMasterKey(testSecret, []byte("salt-a"))

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	mk2, err := rip.NewMasterKey(testSecret, []byte("salt-b"))

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	k1, err := mk1.Derive(rip.ModeDeterministic, rip.KeySize128)

	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	k2, err := mk2.Derive(rip.ModeDeterministic, rip.KeySize128)

	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	d1, err := rip.NewDeterministicEncryption(k1)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	d2, err := rip.NewDeterministicEncryption(k2)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	a, err := d1.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	b, err := d2.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if a == b {
		t.Fatalf("distinct keys produced identical output: %s", a)
	}
}

func Test_DeterministicEncryption_Error_When_Invalid_Address(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	d, err := rip.NewDeterministicEncryption(k)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	if _, err := d.Encrypt(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("Encrypt: got %v, want ErrInvalidIPAddress", err)
	}

	if _, err := d.Decrypt(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("Decrypt: got %v, want ErrInvalidIPAddress", err)
	}
}
