package rip_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

func Test_NewPseudo_Error_When_Wrong_Key_Size(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize128)

	if _, err := rip.NewPseudo(k); !errors.Is(err, rip.ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func Test_Pseudo_Token_Is_Deterministic(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	a, err := p.Token(ip)

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	b, err := p.Token(ip)

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if !rip.TokensEqual(a, b) {
		t.Fatalf("non-determenistic token for %s", ip)
	}
}

func Test_Pseudo_TokenFromScratch_Matches_Token(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	ips := []string{"0.0.0.0", "192.0.2.1", "255.255.255.255", "::", "2001:db8::1"}

	for _, s := range ips {
		ip := netip.MustParseAddr(s)

		want, err := p.Token(ip)

		if err != nil {
			t.Fatalf("Token %s: %v", s, err)
		}

		var scratch rip.ScratchToken

		got, err := p.TokenFromScratch(&scratch, ip)

		if err != nil {
			t.Fatalf("TokenFromScratch %s: %v", s, err)
		}

		if !rip.TokensEqual(got, want) {
			t.Fatalf("scratch token mismatch for %s", s)
		}
	}
}

func Test_Pseudo_Distinct_IPs_Produce_Distinct_Tokens(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	ips := []string{"0.0.0.0", "192.0.2.1", "192.0.2.2", "255.255.255.255", "::", "2001:db8::1"}

	seen := make(map[rip.Token]string, len(ips))

	for _, s := range ips {
		tok, err := p.Token(netip.MustParseAddr(s))

		if err != nil {
			t.Fatalf("Token %s: %v", s, err)
		}

		if prev, ok := seen[tok]; ok {
			t.Fatalf("token collision between %s and %s", prev, s)
		}

		seen[tok] = s
	}
}

func Test_Pseudo_Distinct_Keys_Produce_Distinct_Tokens(t *testing.T) {
	mk1, err := rip.NewMasterKey(testSecret, []byte("salt-a"))

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	mk2, err := rip.NewMasterKey(testSecret, []byte("salt-b"))

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	k1, err := mk1.Derive(rip.ModePseudonym, rip.KeySize256)

	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	k2, err := mk2.Derive(rip.ModePseudonym, rip.KeySize256)

	if err != nil {
		t.Fatalf("Derive: %v", err)
	}

	p1, err := rip.NewPseudo(k1)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	p2, err := rip.NewPseudo(k2)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.1")

	a, err := p1.Token(ip)

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	b, err := p2.Token(ip)

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if rip.TokensEqual(a, b) {
		t.Fatalf("distinct keys produced identical token")
	}
}

func Test_Pseudo_Error_When_Invalid_Address(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	if _, err := p.Token(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("Token: got %v, want ErrInvalidIPAddress", err)
	}

	var scratch rip.ScratchToken

	if _, err := p.TokenFromScratch(&scratch, netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("TokenFromScratch: got %v, want ErrInvalidIPAddress", err)
	}
}

func Test_TokensEqual(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	a, err := p.Token(netip.MustParseAddr("192.0.2.1"))

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	b, err := p.Token(netip.MustParseAddr("192.0.2.2"))

	if err != nil {
		t.Fatalf("Token: %v", err)
	}

	if !rip.TokensEqual(a, a) {
		t.Fatalf("TokensEqual reported equal tokens as different")
	}

	if rip.TokensEqual(a, b) {
		t.Fatalf("TokensEqual reported different tokens as equal")
	}
}

func Test_ScratchToken_Zero_Resets(t *testing.T) {
	k := deriveKey(t, rip.ModePseudonym, rip.KeySize256)

	p, err := rip.NewPseudo(k)

	if err != nil {
		t.Fatalf("NewPseudo: %v", err)
	}

	var scratch rip.ScratchToken

	if _, err := p.TokenFromScratch(&scratch, netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatalf("TokenFromScratch: %v", err)
	}

	scratch.Zero()

	if scratch != (rip.ScratchToken{}) {
		t.Fatalf("Zero did not reset scratch")
	}
}
