//go:build goexperiment.runtimesecret

// Package erase runs code that handles private keys so that its temporaries
// are erased afterwards.
package erase

import "runtime/secret"

// Do runs f under runtime/secret, which erases the registers, stack and heap
// allocations f used once they are no longer needed; it is in effect on
// linux/amd64 and linux/arm64 and calls f directly elsewhere.
func Do(f func()) { secret.Do(f) }
