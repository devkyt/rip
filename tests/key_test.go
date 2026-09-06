package rip_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/devkyt/rip"
)

func Test_NewMasterKey_Error_When_Secret_Too_Short(t *testing.T) {
	if _, err := rip.NewMasterKey([]byte("short"), testSalt); !errors.Is(err, rip.ErrKeySize) {
		t.Fatalf("got %v, want ErrKeySize", err)
	}
}

func Test_NewMasterKey_Allows_Nil_Salt(t *testing.T) {
	if _, err := rip.NewMasterKey(testSecret, nil); err != nil {
		t.Fatalf("NewMasterKey with nil salt: %v", err)
	}
}

func Test_MasterKey_Derive_Error_When_Invalid_Length(t *testing.T) {
	mk := masterKey(t)

	for _, l := range []int{0, 8, 24, 33, 64} {
		if _, err := mk.Derive(rip.ModeDeterministic, l); !errors.Is(err, rip.ErrKeySize) {
			t.Fatalf("Derive length %d: got %v, want ErrKeySize", l, err)
		}
	}
}

func Test_MasterKey_Derive_Returns_Requested_Length(t *testing.T) {
	mk := masterKey(t)

	k128, err := mk.Derive(rip.ModeDeterministic, rip.KeySize128)

	if err != nil {
		t.Fatalf("Derive 128: %v", err)
	}

	if k128.Len() != rip.KeySize128 {
		t.Fatalf("Len: got %d, want %d", k128.Len(), rip.KeySize128)
	}

	k256, err := mk.Derive(rip.ModePseudonym, rip.KeySize256)

	if err != nil {
		t.Fatalf("Derive 256: %v", err)
	}

	if k256.Len() != rip.KeySize256 {
		t.Fatalf("Len: got %d, want %d", k256.Len(), rip.KeySize256)
	}
}

func Test_MasterKey_Derive_Error_When_No_Primary_Key(t *testing.T) {
	var mk rip.MasterKey

	if _, err := mk.Derive(rip.ModeDeterministic, rip.KeySize128); !errors.Is(err, rip.ErrNoPrimaryKey) {
		t.Fatalf("got %v, want ErrNoPrimaryKey", err)
	}
}

func Test_MasterKey_Derive_Is_Deterministic(t *testing.T) {
	mk1, err := rip.NewMasterKey(testSecret, testSalt)

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	mk2, err := rip.NewMasterKey(testSecret, testSalt)

	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}

	if got := deriveAndEncrypt(t, mk1, rip.ModeDeterministic); got != deriveAndEncrypt(t, mk2, rip.ModeDeterministic) {
		t.Fatalf("same secret and salt produced different keys")
	}
}

func Test_MasterKey_Derive_Differs_By_Mode(t *testing.T) {
	mk := masterKey(t)

	if deriveAndEncrypt(t, mk, rip.ModeDeterministic) == deriveAndEncrypt(t, mk, rip.ModePrefix) {
		t.Fatalf("different modes produced identical keys")
	}
}

func Test_MasterKey_Zero_Nil_Safe(t *testing.T) {
	var mk *rip.MasterKey

	mk.Zero()
}

func Test_Key_Is_Redacted(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	const want = "*******"

	if got := k.String(); got != want {
		t.Fatalf("String: got %q, want %q", got, want)
	}

	if got := k.GoString(); got != want {
		t.Fatalf("GoString: got %q, want %q", got, want)
	}

	if got := fmt.Sprintf("%v", k); got != want {
		t.Fatalf("%%v: got %q, want %q", got, want)
	}

	if got := fmt.Sprintf("%s", k); got != want {
		t.Fatalf("%%s: got %q, want %q", got, want)
	}

	if got := fmt.Sprintf("%#v", k); got != want {
		t.Fatalf("%%#v: got %q, want %q", got, want)
	}

	if got := k.LogValue().String(); got != want {
		t.Fatalf("LogValue: got %q, want %q", got, want)
	}
}

func Test_Key_MarshalText_Refuses(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	if _, err := k.MarshalText(); !errors.Is(err, rip.ErrRefuseMarshalKey) {
		t.Fatalf("MarshalText: got %v, want ErrRefuseMarshalKey", err)
	}
}

func Test_Key_Json_Marshal_Refuses(t *testing.T) {
	k := deriveKey(t, rip.ModeDeterministic, rip.KeySize128)

	if _, err := json.Marshal(k); !errors.Is(err, rip.ErrRefuseMarshalKey) {
		t.Fatalf("json.Marshal: got %v, want ErrRefuseMarshalKey", err)
	}
}

func deriveAndEncrypt(t *testing.T, mk *rip.MasterKey, mode rip.Mode) netip.Addr {
	t.Helper()

	k, err := mk.Derive(mode, rip.KeySize128)

	if err != nil {
		t.Fatalf("Derive(%q): %v", mode, err)
	}

	d, err := rip.NewDeterministicEncryption(k)

	if err != nil {
		t.Fatalf("NewDeterministicEncryption: %v", err)
	}

	enc, err := d.Encrypt(netip.MustParseAddr("192.0.2.1"))

	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return enc
}
