//go:build goexperiment.runtimesecret

package dstu4145

import "runtime/secret"

// secretDo runs f under runtime/secret, which erases the registers, stack and
// heap allocations f used once they are no longer needed; it is in effect on
// linux/amd64 and linux/arm64 and calls f directly elsewhere.
func secretDo(f func()) { secret.Do(f) }
