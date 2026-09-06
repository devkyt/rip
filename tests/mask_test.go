package rip_test

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

type maskCase struct {
	in   string
	want string
}

func assertHide(t *testing.T, m *rip.Mask, cases []maskCase) {
	t.Helper()

	for _, c := range cases {
		got, err := m.Hide(netip.MustParseAddr(c.in))

		if err != nil {
			t.Fatalf("Hide %s: %v", c.in, err)
		}

		if want := netip.MustParseAddr(c.want); got != want {
			t.Fatalf("Hide %s: got %s, want %s", c.in, got, want)
		}
	}
}

func Test_New_Mask_Error_When_Wrong_IPv4_Bits_Provided(t *testing.T) {
	for _, i := range []int{-1, -2, 33, 35, 128} {
		if _, err := rip.NewMask(i, 48); !errors.Is(err, rip.ErrInvalidIPBits) {
			t.Fatalf("NewMask ipv4 bits %d: got %v, want ErrInvalidIPBits", i, err)
		}
	}
}

func Test_New_Mask_Error_When_Wrong_IPv6_Bits_Provided(t *testing.T) {
	for _, i := range []int{-1, -2, 129, 200} {
		if _, err := rip.NewMask(16, i); !errors.Is(err, rip.ErrInvalidIPBits) {
			t.Fatalf("NewMask ipv6 bits %d: got %v, want ErrInvalidIPBits", i, err)
		}
	}
}

func Test_Mask_Hide_IPv4_Save_No_Bits(t *testing.T) {
	m, err := rip.NewMask(0, 48)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"192.0.2.130", "0.0.0.0"},
		{"168.4.21.120", "0.0.0.0"},
		{"172.128.0.1", "0.0.0.0"},
	})
}

func Test_Mask_Hide_IPv4_Save_First_8Bits(t *testing.T) {
	m, err := rip.NewMask(8, 48)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"192.0.2.130", "192.0.0.0"},
		{"168.4.21.120", "168.0.0.0"},
		{"172.128.0.1", "172.0.0.0"},
	})
}

func Test_Mask_Hide_IPv4_Save_First_16Bits(t *testing.T) {
	assertHide(t, rip.DefaultMask(), []maskCase{
		{"192.0.2.130", "192.0.0.0"},
		{"168.4.21.120", "168.4.0.0"},
		{"172.128.0.1", "172.128.0.0"},
	})
}

func Test_Mask_Hide_IPv4_Save_First_24Bits(t *testing.T) {
	m, err := rip.NewMask(24, 48)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"192.0.2.130", "192.0.2.0"},
		{"168.4.21.120", "168.4.21.0"},
		{"172.128.0.1", "172.128.0.0"},
	})
}

func Test_Mask_Hide_IPv6_Save_No_Bits(t *testing.T) {
	m, err := rip.NewMask(16, 0)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "::"},
		{"fe80:1:2:3:4:5:6:7", "::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::"},
	})
}

func Test_Mask_Hide_IPv6_Save_First_16Bits(t *testing.T) {
	m, err := rip.NewMask(16, 16)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "2001::"},
		{"fe80:1:2:3:4:5:6:7", "fe80::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff::"},
	})
}

func Test_Mask_Hide_IPv6_Save_First_32Bits(t *testing.T) {
	m, err := rip.NewMask(16, 32)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "2001:db8::"},
		{"fe80:1:2:3:4:5:6:7", "fe80:1::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff::"},
	})
}

func Test_Mask_Hide_IPv6_Save_First_48Bits(t *testing.T) {
	assertHide(t, rip.DefaultMask(), []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "2001:db8:abcd::"},
		{"fe80:1:2:3:4:5:6:7", "fe80:1:2::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff::"},
	})
}

func Test_Mask_Hide_IPv6_Save_First_64Bits(t *testing.T) {
	m, err := rip.NewMask(16, 64)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "2001:db8:abcd:1234::"},
		{"fe80:1:2:3:4:5:6:7", "fe80:1:2:3::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff::"},
	})
}

func Test_Mask_Hide_IPv6_Save_All_Bits(t *testing.T) {
	m, err := rip.NewMask(16, 128)

	if err != nil {
		t.Fatalf("NewMask: %v", err)
	}

	assertHide(t, m, []maskCase{
		{"2001:db8:abcd:1234:5678:9abc:def0:1111", "2001:db8:abcd:1234:5678:9abc:def0:1111"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	})
}

func Test_Mask_Hide_Unmaps_IPv4_Mapped_IPv6(t *testing.T) {
	assertHide(t, rip.DefaultMask(), []maskCase{
		{"::ffff:192.0.2.130", "192.0.0.0"},
		{"::ffff:168.4.21.120", "168.4.0.0"},
	})
}

func Test_Mask_Hide_Error_When_Invalid_Address_Provided(t *testing.T) {
	m := rip.DefaultMask()

	if _, err := m.Hide(netip.Addr{}); !errors.Is(err, rip.ErrInvalidIPAddress) {
		t.Fatalf("got %v, want ErrInvalidIPAddress", err)
	}
}
