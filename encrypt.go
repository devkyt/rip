package rip

type EncryptionType string

const (
	Determenistic EncryptionType = "determenistic"
	Prefx         EncryptionType = "prefix"
)

type MasterKey struct {
	prk []byte
}
