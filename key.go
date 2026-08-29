package rip

import (
	"errors"
	"log/slog"
)

var (
	ErrRefuseMarshalKey = errors.New("rip: refuse to marshal key")
)

type EncryptionType string

const (
	Determenistic EncryptionType = "determenistic"
	Prefx         EncryptionType = "prefix"
)

type MasterKey struct {
	prk []byte
}

type Key struct {
	b []byte
}

func (k Key) String() string { return "*******" }

func (k Key) GoString() string { return "*******" }

func (k Key) LogValue() slog.Value { return slog.StringValue("*******") }

func (k Key) MarshalText() ([]byte, error) {
	return nil, ErrRefuseMarshalKey
}

func (k Key) Zero() { clear(k.b) }
