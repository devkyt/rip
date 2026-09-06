package rip_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

func Test_NewPrefix_Error_When_Wrong_Key_Size(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize128)

	if _, err := rip.NewPrefix(k); !errors.Is(err, rip.ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func Test_Prefix_Round_Trip(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
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

		enc, err := p.Encrypt(ip)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", s, err)
		}

		dec, err := p.Decrypt(enc)

		if err != nil {
			t.Fatalf("Decrypt %s: %v", s, err)
		}

		if dec != ip {
			t.Fatalf("round trip %s: got %s, want %s", s, dec, ip)
		}
	}
}

func Test_Prefix_Preserves_Address_Family(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}

	ips := []string{"192.0.2.1", "255.255.255.255", "2001:db8::1", "::"}

	for _, s := range ips {
		ip := netip.MustParseAddr(s)

		enc, err := p.Encrypt(ip)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", s, err)
		}

		if enc.Is4() != ip.Is4() {
			t.Fatalf("Encrypt %s changed family: got %s", s, enc)
		}
	}
}

func Test_Prefix_Preserves_Common_Prefix_Length(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}

	pairs := []struct {
		a, b string
	}{
		{"192.0.2.1", "192.0.2.254"},
		{"192.0.2.1", "192.0.3.1"},
		{"10.0.0.1", "10.128.0.1"},
		{"0.0.0.0", "255.255.255.255"},
		{"2001:db8::1", "2001:db8::2"},
		{"2001:db8:1::", "2001:db9:1::"},
	}

	for _, pr := range pairs {
		a := netip.MustParseAddr(pr.a)
		b := netip.MustParseAddr(pr.b)

		ea, err := p.Encrypt(a)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", pr.a, err)
		}

		eb, err := p.Encrypt(b)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", pr.b, err)
		}

		want := commonPrefixLen(t, a, b)
		got := commonPrefixLen(t, ea, eb)

		if got != want {
			t.Fatalf("common prefix %s/%s: got %d, want %d", pr.a, pr.b, got, want)
		}
	}
}

func Test_Prefix_Is_Deterministic(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	a, err := p.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	b, err := p.Encrypt(ip)

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if a != b {
		t.Fatalf("non-determenistic output: %s != %s", a, b)
	}
}

func Test_Prefix_Scratch_Matches_Non_Scratch(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}

	ips := []string{"192.0.2.1", "255.255.255.255", "2001:db8::1"}

	for _, s := range ips {
		ip := netip.MustParseAddr(s)

		enc, err := p.Encrypt(ip)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", s, err)
		}

		var se rip.ScratchPrefix

		encScratch, err := p.EncryptScratch(&se, ip)

		if err != nil {
			t.Fatalf("EncryptScratch %s: %v", s, err)
		}

		if enc != encScratch {
			t.Fatalf("EncryptScratch %s: got %s, want %s", s, encScratch, enc)
		}

		var sd rip.ScratchPrefix

		dec, err := p.DecryptScratch(&sd, enc)

		if err != nil {
			t.Fatalf("DecryptScratch %s: %v", s, err)
		}

		if dec != ip {
			t.Fatalf("DecryptScratch %s: got %s, want %s", s, dec, ip)
		}
	}
}

func Test_Prefix_Error_When_Invalid_Address(t *testing.T) {
	k := deriveKey(t, rip.ModePrefix, rip.KeySize256)

	p, err := rip.NewPrefix(k)

	if err != nil {
		t.Fatalf("NewPrefix: %v", err)
	}

	if _, err := p.Encrypt(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("Encrypt: got %v, want ErrInvalidIPAddress", err)
	}

	if _, err := p.Decrypt(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("Decrypt: got %v, want ErrInvalidIPAddress", err)
	}

	var s rip.ScratchPrefix

	if _, err := p.EncryptScratch(&s, netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("EncryptScratch: got %v, want ErrInvalidIPAddress", err)
	}

	if _, err := p.DecryptScratch(&s, netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("DecryptScratch: got %v, want ErrInvalidIPAddress", err)
	}
}
