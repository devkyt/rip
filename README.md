# RIP

RIP — is a dependency free (yeah baby) Golang library that will help you to hide and obfuscate IP addresses of users.

## Supported Modes

### Mask
Specify the size of mask for IPv4 and IPv6 adresses or use the default mask (16, 48). 
Anything that does not match the mask will be dropped to 0. 

```golang
m  := rip.DefaultMask()
ip := m.Hide("192.168.0.4") // 192.168.0.0

m := rip.NewMask(8, 48)
ip := m.Hide("192.168.0.4") // 192.0.0.0    
```


### Determenistic Encryption

```golang
d := rip.NewDetermenisticEncryption()

en  := d.encrypt("192.168.0.4")
de  := d.decrypt(e)
```

