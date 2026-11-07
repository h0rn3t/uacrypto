//go:build !goexperiment.runtimesecret

// Package erase runs code that handles private keys so that its temporaries
// are erased afterwards.
package erase

// Do runs f. Built with GOEXPERIMENT=runtimesecret, it runs f under
// runtime/secret instead (erase.go).
func Do(f func()) { f() }
