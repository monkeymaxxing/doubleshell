module doubleshell

go 1.27.0

toolchain go1.27.3

require (
	golang.zx2c4.com/wireguard v0.0.0-20261024220952-b3bc704ef0ee
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

// Build with the reviewed, pruned dependency copies. See docs/design.md.
replace (
	github.com/google/btree => ./third_party/github.com/google/btree
	golang.org/x/crypto => ./third_party/golang.org/x/crypto
	golang.org/x/net => ./third_party/golang.org/x/net
	golang.org/x/sys => ./third_party/golang.org/x/sys
	golang.org/x/time => ./third_party/golang.org/x/time
	golang.zx2c4.com/wireguard => ./third_party/golang.zx2c4.com/wireguard
	gvisor.dev/gvisor => ./third_party/gvisor.dev/gvisor
)
