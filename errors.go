package rip

import "errors"

var (
	ErrInvalidIPBits    = errors.New("rip: unsufficient IP bits")
	ErrInvalidIPAddress = errors.New("rip: invalid IP")

	ErrKeySize          = errors.New("rip: unsufficient key size")
	ErrNoPrimaryKey     = errors.New("rip: no primary key")
	ErrRefuseMarshalKey = errors.New("rip: refuse to marshal key")
)
