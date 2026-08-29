package rip_test

import (
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

func Test_Default_Mask_Hide_IPv4(t *testing.T) {
	m := rip.DefaultMask()

	tests := []struct {
		in   string
		want string
	}{
		{"192.0.2.130", "192.0.0.0"},
		{"168.4.21.120", "168.4.0.0"},
		{"172.128.0.1", "172.128.0.0"},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.in)

		got, err := m.Hide(ip)

		if err != nil {
			t.Fatalf("Hide %s: %v", test.in, err)
		}

		want := netip.MustParseAddr(test.want)

		if got != want {
			t.Fatalf("Hide %s saving first 16 bits: got %s, want %s", test.in, got, want)
		}
	}
}

func Test_Mask_Hide_IPv4_Save_First_8Bits(t *testing.T) {
	m, _ := rip.NewMask(8, 48)

	tests := []struct {
		in   string
		want string
	}{
		{"192.0.2.130", "192.0.0.0"},
		{"168.4.21.120", "168.0.0.0"},
		{"172.128.0.1", "172.0.0.0"},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.in)

		got, err := m.Hide(ip)

		if err != nil {
			t.Fatalf("Hide %s: %v", test.in, err)
		}

		want := netip.MustParseAddr(test.want)

		if got != want {
			t.Fatalf("Hide %s saving first 8 bits: got %s, want %s", test.in, got, want)
		}
	}
}

func Test_Mask_Hide_IPv4_Save_First_16Bits(t *testing.T) {
	m := rip.DefaultMask()

	tests := []struct {
		in   string
		want string
	}{
		{"192.0.2.130", "192.0.0.0"},
		{"168.4.21.120", "168.4.0.0"},
		{"172.128.0.1", "172.128.0.0"},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.in)

		got, err := m.Hide(ip)

		if err != nil {
			t.Fatalf("Hide %s: %v", test.in, err)
		}

		want := netip.MustParseAddr(test.want)

		if got != want {
			t.Fatalf("Hide %s saving first 16 bits: got %s, want %s", test.in, got, want)
		}
	}
}

func Test_Mask_Hide_IPv4_Save_First_24Bits(t *testing.T) {
	m, _ := rip.NewMask(24, 48)

	tests := []struct {
		in   string
		want string
	}{
		{"192.0.2.130", "192.0.2.0"},
		{"168.4.21.120", "168.4.21.0"},
		{"172.128.0.1", "172.128.0.0"},
	}

	for _, test := range tests {
		ip := netip.MustParseAddr(test.in)

		got, err := m.Hide(ip)

		if err != nil {
			t.Fatalf("Hide %s: %v", test.in, err)
		}

		want := netip.MustParseAddr(test.want)

		if got != want {
			t.Fatalf("Hide %s under 24 bit mask: got %s, want %s", test.in, got, want)
		}
	}
}
