package rip

// Known-answer tests against the official ipcrypt specification
// (draft-denis-ipcrypt-11, Appendix "Test Vectors"). These use raw AES keys
// exactly as published, so they live in the internal package where a Key can
// be built directly from key material.

import (
	"encoding/hex"
	"net/netip"
	"testing"
)

func rawKey(t *testing.T, h string) Key {
	t.Helper()

	b, err := hex.DecodeString(h)

	if err != nil {
		t.Fatalf("decode key %q: %v", h, err)
	}

	return Key{b: b}
}

// https://datatracker.ietf.org/doc/html/draft-denis-ipcrypt-11 — ipcrypt-deterministic
func Test_Spec_Deterministic_Vectors(t *testing.T) {
	cases := []struct {
		key, ip, want string
	}{
		{"0123456789abcdeffedcba9876543210", "0.0.0.0", "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"},
		{"1032547698badcfeefcdab8967452301", "255.255.255.255", "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"},
		{"2b7e151628aed2a6abf7158809cf4f3c", "192.0.2.1", "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777"},
	}

	for _, c := range cases {
		d, err := NewDeterministicEncryption(rawKey(t, c.key))

		if err != nil {
			t.Fatalf("NewDeterministicEncryption %s: %v", c.ip, err)
		}

		in := netip.MustParseAddr(c.ip)

		enc, err := d.Encrypt(in)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", c.ip, err)
		}

		if enc.String() != c.want {
			t.Fatalf("Encrypt %s: got %s, want %s", c.ip, enc, c.want)
		}

		dec, err := d.Decrypt(enc)

		if err != nil {
			t.Fatalf("Decrypt %s: %v", c.ip, err)
		}

		if dec != in.Unmap() {
			t.Fatalf("round trip %s: got %s", c.ip, dec)
		}
	}
}

// https://datatracker.ietf.org/doc/html/draft-denis-ipcrypt-11 — ipcrypt-pfx (32-byte key)
func Test_Spec_Prefix_Vectors(t *testing.T) {
	const (
		keyBasic  = "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
		keyPrefix = "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a"
	)

	cases := []struct {
		key, ip, want string
	}{
		{keyBasic, "0.0.0.0", "151.82.155.134"},
		{keyBasic, "255.255.255.255", "94.185.169.89"},
		{keyBasic, "192.0.2.1", "100.115.72.131"},
		{keyBasic, "2001:db8::1", "c180:5dd4:2587:3524:30ab:fa65:6ab6:f88"},

		{keyPrefix, "10.0.0.47", "19.214.210.244"},
		{keyPrefix, "10.0.0.129", "19.214.210.80"},
		{keyPrefix, "10.0.0.234", "19.214.210.30"},

		{keyPrefix, "172.16.5.193", "210.78.229.136"},
		{keyPrefix, "172.16.97.42", "210.78.179.241"},
		{keyPrefix, "172.16.248.177", "210.78.121.215"},

		{keyPrefix, "2001:db8::a5c9:4e2f:bb91:5a7d", "7cec:702c:1243:f70:1956:125:b9bd:1aba"},
		{keyPrefix, "2001:db8::7234:d8f1:3c6e:9a52", "7cec:702c:1243:f70:a3ef:c8e:95c1:cd0d"},
		{keyPrefix, "2001:db8::f1e0:937b:26d4:8c1a", "7cec:702c:1243:f70:443c:c8e:6a62:b64d"},

		{keyPrefix, "2001:db8:3a5c:0:e7d1:4b9f:2c8a:f673", "7cec:702c:3503:bef:e616:96bd:be33:a9b9"},
		{keyPrefix, "2001:db8:9f27:0:b4e2:7a3d:5f91:c8e6", "7cec:702c:a504:b74e:194a:3d90:b047:2d1a"},
		{keyPrefix, "2001:db8:d8b4:0:193c:a5e7:8b2f:46d1", "7cec:702c:f840:aa67:1b8:e84f:ac9d:77fb"},
	}

	for _, c := range cases {
		p, err := NewPrefix(rawKey(t, c.key))

		if err != nil {
			t.Fatalf("NewPrefix %s: %v", c.ip, err)
		}

		in := netip.MustParseAddr(c.ip)

		enc, err := p.Encrypt(in)

		if err != nil {
			t.Fatalf("Encrypt %s: %v", c.ip, err)
		}

		if enc.String() != c.want {
			t.Fatalf("Encrypt %s: got %s, want %s", c.ip, enc, c.want)
		}

		dec, err := p.Decrypt(enc)

		if err != nil {
			t.Fatalf("Decrypt %s: %v", c.ip, err)
		}

		if dec != in {
			t.Fatalf("round trip %s: got %s", c.ip, dec)
		}
	}
}
