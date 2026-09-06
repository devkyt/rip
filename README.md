# RIP

**Rip** is a dependency-free (yeah baby) Go library that helps you hide and
obfuscate the IP addresses of your users.

All modes operate on `net/netip.Addr` and support both IPv4 and IPv6.

## Keys

The reversible and pseudonym modes take a `Key` derived from a master
secret via HKDF. Derive one key per mode so the modes stay cryptographically
independent:

```go
mk, err := rip.NewMasterKey(secret, salt) // secret must be >= 16 bytes
if err != nil {
	// ...
}

key, err := mk.Derive(rip.Deterministic, rip.KeySize128)
```

`Key` redacts itself in logs and refuses to marshal, so don't worry - it will not leak into
your logs or JSON.

## Supported Modes

### Mask — non-reversible

Keep the first N bits and zero the rest. Use `DefaultMask` (16 for IPv4,
48 for IPv6) or set your own with `NewMask`.

```go
m := rip.DefaultMask()
ip, _ := m.Hide(netip.MustParseAddr("192.168.0.4")) // 192.168.0.0

m, _ = rip.NewMask(8, 48)
ip, _ = m.Hide(netip.MustParseAddr("192.168.0.4"))  // 192.0.0.0
```

### Pseudonym — non-reversible

Maps an address to a stable, opaque 16-byte token. The same address always
yields the same token. Keep in mind that the token cannot be turned back into the address.

Requires a 256-bit key.

```go
key, _ := mk.Derive(rip.Pseudonym, rip.KeySize256)

p, _ := rip.NewPseudo(key)

tok, _ := p.Token(netip.MustParseAddr("192.0.2.1"))

rip.TokensEqual(tok, tok) // constant-time comparison
```

### Deterministic encryption — reversible

Encrypts an address to another address of the same family. The same input
always maps to the same output. 

Requires a 128-bit key.

```go
key, _ := mk.Derive(rip.Deterministic, rip.KeySize128)

d, _ := rip.NewDeterministicEncryption(key)

enc, _ := d.Encrypt(netip.MustParseAddr("192.0.2.1"))
dec, _ := d.Decrypt(enc)
```

### Prefix — reversible, prefix-preserving

Like deterministic encryption, but saves the common prefix length between
addresses. In short, two inputs that share a prefix produce outputs that share a prefix
of the same length. Use when you need to keep subnet structure while hiding
the actual addresses. 

Requires a 256-bit key.

```go
key, _ := mk.Derive(rip.Prefx, rip.KeySize256)

p, _ := rip.NewPrefix(key)

enc, _ := p.Encrypt(netip.MustParseAddr("192.0.2.1"))
dec, _ := p.Decrypt(enc)
```

Methods (`EncryptScratch`, `DecryptScratch`, `TokenFromScratch`)
accept a caller-owned scratch buffer to avoid per-call allocations.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Kyrylo Tykhanskyi.
