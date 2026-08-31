package rip

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"log/slog"
)

var (
	ErrKeySize          = errors.New("rip: unsufficient key size")
	ErrNoPrimaryKey     = errors.New("rip: no primary key")
	ErrRefuseMarshalKey = errors.New("rip: refuse to marshal key")
)

const (
	MasterKeySize = 32
	KeySize128    = 16
	KeySize256    = 32
)

type EncryptionType string

const (
	Determenistic EncryptionType = "determenistic"
	Prefx         EncryptionType = "prefix"
)

type MasterKey struct {
	prk []byte
}

func NewMasterKey(secret, salt []byte) (*MasterKey, error) {
	if len(secret) < KeySize128 {
		return nil, ErrKeySize
	}

	prk, err := hkdf.Extract(sha256.New, secret, salt)

	if err != nil {
		return nil, err
	}

	return &MasterKey{prk: prk}, nil
}

func (m *MasterKey) Derive(t EncryptionType, l int) (Key, error) {
	if len(m.prk) == 0 {
		return Key{}, ErrNoPrimaryKey
	}

	if l != KeySize128 && l != KeySize256 {
		return Key{}, ErrKeySize
	}

	b, err := hkdf.Expand(sha256.New, m.prk, string(t), l)

	if err != nil {
		return Key{}, err
	}

	return Key{b: b}, nil
}

type Key struct {
	b []byte
}

func (k Key) String() string { return "*******" }

func (k Key) GoString() string { return "*******" }

func (k Key) LogValue() slog.Value { return slog.StringValue("*******") }

func (k Key) Len() int { return len(k.b) }

func (k Key) MarshalText() ([]byte, error) { return nil, ErrRefuseMarshalKey }

func (k Key) Zero() { clear(k.b) }

func (k Key) bytes() []byte { return k.b }
