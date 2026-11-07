//go:build !goexperiment.runtimesecret

package dstu4145

// secretDo runs f. Built with GOEXPERIMENT=runtimesecret, it runs f under
// runtime/secret instead (secret.go).
func secretDo(f func()) { f() }
