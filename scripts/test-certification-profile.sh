#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local
export GOEXPERIMENT=runtimesecret
export CGO_ENABLED=0

if [ "$(go env GOVERSION)" != go1.27.3 ]; then
  echo 'The candidate profile requires Go 1.27.3.' >&2
  exit 1
fi
if [ "$(go env GOHOSTOS)" != linux ] || [ "$(go env GOOS)" != linux ]; then
  echo 'The candidate profile requires Linux; runtime/secret is ineffective on other operating systems.' >&2
  exit 1
fi
case "$(go env GOARCH)" in
  amd64|arm64) ;;
  *) echo 'The candidate profile requires amd64 or arm64.' >&2; exit 1 ;;
esac
if [ "$(go env GOARCH)" != "$(go env GOHOSTARCH)" ]; then
  echo 'Run the profile natively, without cross-compiling the test binaries.' >&2
  exit 1
fi

echo 'uacrypto candidate profile; this is not an expert conclusion.'
go env GOVERSION GOHOSTOS GOHOSTARCH GOOS GOARCH GOEXPERIMENT CGO_ENABLED
git rev-parse HEAD
git status --short
echo 'SHA-256 of the sorted source manifest, including untracked non-ignored files:'
git ls-files --cached --others --exclude-standard -z | LC_ALL=C sort -zu | xargs -0 sha256sum | sha256sum
go vet ./...
go test -count=1 -timeout=15m ./...
