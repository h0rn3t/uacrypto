# Constant-Time Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every operation on a secret (DSTU 4145 keys and signing, Kalyna, Kupyna, GOST 28147) runs without secret-dependent branches or memory addresses, a dudect-style timing test in GitHub Actions blocks the release, and the README warning goes.

**Architecture:** DSTU 4145 moves from `math/big` to fixed `[7]uint64` limbs: a GF(2^m) field, a López–Dahab Montgomery ladder for secret scalars, and Montgomery arithmetic mod n. Public-only paths (`Verify`, `ParsePublicKey`) use the same field with a variable-time affine double-and-add. S-box lookups in `internal/spn` and `gost28147` become full masked table scans. A new `internal/ctcheck` package holds the Welch t-test harness; its build-tagged test times exported APIs.

**Tech Stack:** Go 1.27, standard library only (`math/bits`, `crypto/subtle`, `math/rand/v2` for test input generation).

**Spec:** `docs/superpowers/specs/2026-11-05-constant-time-design.md` (Ukrainian; read it first).

## Global Constraints

- Standard library only; no new module in `go.mod`.
- No change to any output or API: existing vector tests and `make -C parity` pass with unchanged expected values. `Sign` still returns `r, s *big.Int`; `Verify` still takes them.
- Constant time is required for: `GenerateKey`, `NewPrivateKey`, `Sign`, `PrivateKey.Bytes`, Kalyna key schedule/`Encrypt`/`Decrypt`, Kupyna compression, GOST 28147 round. Not required for `Verify`, `ParsePublicKey`, `PublicKey.Bytes`, `CurveFromParams`, `pki`.
- Correct on 32-bit (`GOARCH=386`); constant time claimed for 64-bit, verified on linux/amd64.
- Timing test: |t| > 10 fails, no retries; negative control must reach |t| > 10 or the test fails; representatives only: M257, Kalyna-128, Kupyna-256, GOST 28147 with DKE1. If too slow, the list shrinks, never the threshold.
- Comments, godoc, test messages, commits in English; README in Ukrainian.
- Gate before each commit: `gofmt -l .` empty, `go vet ./...`, `golangci-lint run ./...`, `go test -race -count=1 ./...`.
- Commit only when the user has said so (CLAUDE.md). Commit subjects follow the history: imperative English, e.g. "Run the DSTU 4145 field on fixed limbs".

## Review Focus

1. Ladder edge scalars k = 1, 2, n−2, n−1 (intermediate or final (k+1)P is the point at infinity) — must equal the variable-time result. Test in Task 2.
2. `NewPrivateKey` with leading zero bytes, with `d = n−1`, with input longer than the order's byte length — same accept/reject as today. Test in Task 3.
3. Hash that maps to zero (replaced by 1) still signs and verifies — covered by existing `TestSignVerify` "zero"; keep it passing.
4. 32-bit builds: limb code built on `bits.Mul64`/shifts must stay correct under `GOARCH=386`. CI step in Task 4.
5. Concurrent `Sign` on one shared `*Curve` must not race (precomputed tables are read-only). `go test -race` over `TestSignVerify` (parallel subtests) plus a parallel sign test on one curve in Task 3.

---

### Task 1: GF(2^m) on fixed limbs

**Files:**
- Modify: `dstu4145/field.go` (rewrite)
- Create: `dstu4145/field_ref_test.go` (today's `big.Int` field, moved verbatim, renamed `refField`/`newRefField`)
- Create: `dstu4145/field_test.go`
- Modify: `dstu4145/curve.go`, `dstu4145/dstu4145.go` (callers switch to `felem`; behaviour unchanged)

**Interfaces:**
- Produces:
  - `type felem [7]uint64` — bit i of the little-endian limbs is the coefficient of x^i; reduced elements are below 2^m.
  - `type field struct { m int; ks []int }` and `newField(m int, ks ...int) field` (same call sites as today; `ks` sorted).
  - `func (f *field) add(a, b felem) felem`, `mul(a, b felem) felem`, `sqr(a felem) felem`, `inv(a felem) felem` (Fermat a^(2^m−2), inv(0) = 0), `trace(a felem) uint64`, `sqrt(a felem) felem`, `solveQuadratic(beta felem) (felem, bool)`.
  - `func feFromBig(x *big.Int) felem`, `func (a felem) big() *big.Int`, `func (a felem) isZero() bool` (constant-time OR of limbs), `func (a felem) equal(b felem) bool`.
- `mul`, `sqr`, `inv`, `add`: no branch or index on element values; loop counts depend only on m and ks. Carry-less 64×64 multiply by 64 masked iterations (as `kalyna/field.go`), schoolbook into 14 limbs, reduction by shifts of the public m and ks (every k < m−64 for the ten curves, so two folding passes suffice).
- `trace`, `sqrt`, `solveQuadratic` are used only on public data but must also be built from the new `mul`/`sqr`.

- [ ] **Step 1: Move the current field into `field_ref_test.go`** as `refField` with `newRefField`; it is the test oracle (validated against BC by today's vectors).
- [ ] **Step 2: Write `TestFieldMatchesReference`** in `field_test.go`: for each of the 10 named curves' fields, 200 pairs from a seeded `math/rand/v2` ChaCha8 plus edge values {0, 1, x^(m−1), 2^m−1}: `mul`, `sqr`, `add` equal the reference; `inv(a)` equals reference for a ≠ 0 and `mul(a, inv(a)) == 1`; `trace`, `sqrt`, `solveQuadratic` (both result and ok) equal the reference. Failure message names curve m and the operands in hex.
- [ ] **Step 3: Run** `go test ./dstu4145 -run TestFieldMatchesReference` — Expected: FAIL (does not compile: `felem` undefined).
- [ ] **Step 4: Implement** the field per Interfaces; switch `curve.go` and `dstu4145.go` to `felem` (`Curve.b`, `point{x, y felem}` plus an `inf bool`, `Curve.a` becomes `uint64` 0/1). `CurveFromParams` compares m, sorted ks, a, b, n, G.
- [ ] **Step 5: Run** `go test -race -count=1 ./dstu4145 ./pki` — Expected: PASS, including `TestBouncyCastleVectors`, `TestIITSignature`, `TestCurveFromParams`.
- [ ] **Step 6: Gate and commit** "Run the DSTU 4145 field on fixed limbs".

### Task 2: Montgomery ladder for secret scalars

**Files:**
- Modify: `dstu4145/curve.go`
- Create: `dstu4145/curve_test.go`

**Interfaces:**
- Consumes: `felem`, `field` methods (Task 1); `scalar`, `scalarFromBig`, `Curve.ord.nbits` (Task 3 — do Task 3 before this one).
- Produces:
  - `func (c *Curve) scalarMult(p point, k *scalar) point` — constant time; requires p of order n with x ≠ 0, k in [1, n−1]; returns an affine point.
  - `func (c *Curve) scalarMultVartime(p point, k *big.Int) point` — today's double-and-add renamed, on `felem`; used by `Verify` and the subgroup check in `ParsePublicKey`, and as the test oracle.
- Algorithm: López–Dahab x-only ladder in projective (X, Z): start (X1, Z1) = (x, 1), (X2, Z2) = (x^4 + b, x^2); per bit a masked conditional swap (`felem` swap by mask, no branch), Madd and Mdouble; recover y with the López–Dahab Mxy formula and one `inv`. Fixed length: k̃ = k + n, and if bit `nbits` of k̃ is 0 add n again (masked select), so the ladder always runs `nbits` steps below the fixed top bit, where `nbits = c.n.BitLen()`. The case (k+1)P = ∞ (k = n−1) must come out right with masked selects, not branches.

- [ ] **Step 1: Write `TestScalarMultMatchesVartime`**: for curves M163, M257, M431 and the base point G: k ∈ {1, 2, 3, n−2, n−1} plus 20 seeded random k in [1, n−1]: `scalarMult(G, k)` equals `scalarMultVartime(G, k)` (x and y). Also one random subgroup point Q = scalarMultVartime(G, rnd) as the base.
- [ ] **Step 2: Run** `go test ./dstu4145 -run TestScalarMultMatchesVartime` — Expected: FAIL (undefined).
- [ ] **Step 3: Implement** the ladder; switch `newPrivateKey` and `Sign` to `scalarMult`; `Verify` and `ParsePublicKey` to `scalarMultVartime`.
- [ ] **Step 4: Run** `go test -race -count=1 ./dstu4145 ./pki` — Expected: PASS.
- [ ] **Step 5: Gate and commit** "Multiply secret scalars with a Montgomery ladder".

### Task 3: Scalars mod n and the private key

**Files:**
- Create: `dstu4145/scalar.go`, `dstu4145/scalar_test.go`
- Modify: `dstu4145/curve.go` (`Curve` gains precomputed `order` data), `dstu4145/dstu4145.go`

**Interfaces:**
- Produces:
  - `type scalar [7]uint64` (little-endian limbs).
  - `type order struct { n scalar; nbits int; n0inv uint64; rr scalar }` — Montgomery constants computed with `big.Int` once per curve (public); field `Curve.ord order`.
  - `func (o *order) mulAdd(r, d, e *scalar) scalar` — (r·d + e) mod n, constant time (Montgomery multiply, then multiply by R² to leave the Montgomery domain, add e, masked conditional subtract).
  - `func (o *order) fromBytes(be []byte) (scalar, bool)` — big-endian input of any length; ok iff 1 ≤ value ≤ n−1; the comparison is constant time; length and nonzero leading bytes beyond the order's byte length may branch (length is public).
  - `func (o *order) bytes(k *scalar) []byte` — big-endian, padded to `(nbits+7)/8`.
  - `func scalarFromBig(x *big.Int) scalar`, `func (k *scalar) big() *big.Int` — only for public values (r, s) and tests.
  - `func (o *order) isZero(k *scalar) bool`.
  - `randomScalar(c *Curve, random io.Reader) (scalar, error)` — read `(nbits+7)/8` bytes, clear bits ≥ nbits, accept via `fromBytes`, else retry; read errors wrap as today: `"dstu4145: read random: %w"`.
  - `PrivateKey.d` becomes `scalar`.

- [ ] **Step 1: Write `TestMulAddMatchesBig`**: for all 10 curves, 100 seeded triples plus r, d, e ∈ {0, 1, n−1} combinations: `mulAdd` equals `(r*d+e) mod n` by `big.Int`.
- [ ] **Step 2: Write `TestOrderFromBytes`**: accepts 1, n−1, n−1 with two leading zero bytes; rejects nil, {0}, n, n+1, 2^(8·size), and a size+1-byte value with a nonzero top byte. Expected values computed with `big.Int` in the test.
- [ ] **Step 3: Write `TestRandomScalarRange`**: with a reader that first yields all-0xff bytes (≥ n after masking on M257, so rejected) then a fixed valid value, `randomScalar` returns that value; with `iotest.ErrReader(io.ErrUnexpectedEOF)` the error satisfies `errors.Is(err, io.ErrUnexpectedEOF)`.
- [ ] **Step 4: Write `TestSignConcurrent`**: one M257 key, 8 goroutines × 10 `Sign`/`Verify` on one shared curve; run under `-race`.
- [ ] **Step 5: Run** `go test ./dstu4145 -run 'TestMulAdd|TestOrderFromBytes|TestRandomScalar|TestSignConcurrent'` — Expected: FAIL (undefined).
- [ ] **Step 6: Implement** per Interfaces; `NewPrivateKey` uses `fromBytes` (error text unchanged: `"dstu4145: private key out of range [1, n-1]"`), `Bytes` uses `bytes`, `Sign` computes `s` with `mulAdd` and retries on `isZero(s)`; `r` stays computed from public `R.x` and the hash.
- [ ] **Step 7: Run** `go test -race -count=1 ./dstu4145 ./pki` and, if Java/cargo/bun are installed, `make -C parity` — Expected: PASS; `TestNewPrivateKeyRejects` unchanged and passing.
- [ ] **Step 8: Gate and commit** "Keep the DSTU 4145 private scalar out of math/big".

### Task 4: Constant-time S-boxes and GF(2^8) in Kalyna, Kupyna, GOST

**Files:**
- Modify: `internal/spn/spn.go`, `kalyna/kalyna.go`, `kupyna/kupyna.go`, `gost28147/gost28147.go`, `.github/workflows/test.yml`
- Create: `internal/spn/spn_test.go`; test in `gost28147/gost28147_test.go`

**Interfaces:**
- Produces:
  - `func spn.Lookup(table *[256]byte, x byte) byte` — scans all 256 entries, selects by a mask from `subtle.ConstantTimeByteEq`.
  - `spn.Mul(a, b byte) byte` — exactly 8 iterations, masks instead of `if`.
  - in `gost28147`: `func lookup16(row *[16]byte, x uint32) uint32` — scans 16 entries by mask.
- Every `spn.Sbox[...][x]` and `sboxInv[...][x]` in `kalyna.round`, `kalyna.invRound`, `kupyna.mixRound` becomes `spn.Lookup`. `gostCipher.round` uses `lookup16`.

- [ ] **Step 1: Write `TestLookup`** (all 4 S-boxes × 256 x: `Lookup(&Sbox[i], x) == Sbox[i][x]`) and **`TestMul`** (all 65536 pairs equal a reference `refMul` copied in the test file from today's `Mul`; plus `Mul(0x02, 0x80) == 0x1d`). **`TestLookup16`** in gost28147: all 8 rows of DKE1 × 16 values.
- [ ] **Step 2: Run** `go test ./internal/spn ./gost28147` — Expected: FAIL (undefined `Lookup`, `lookup16`).
- [ ] **Step 3: Implement** and switch the call sites.
- [ ] **Step 4: Extend the 32-bit CI step** in `test.yml`: `GOARCH=386 CGO_ENABLED=0 go test ./kalyna ./kupyna ./gost28147 ./internal/spn ./dstu4145` (rename the step "Test on 32-bit Go"). Run it locally — Expected: PASS.
- [ ] **Step 5: Run** `go test -race -count=1 ./...` — Expected: PASS (all Kalyna/Kupyna/GOST/GOST 34.311 vectors unchanged).
- [ ] **Step 6: Gate and commit** "Look up S-boxes by a full masked scan".

### Task 5: dudect harness and timing tests

**Files:**
- Create: `internal/ctcheck/ctcheck.go`, `internal/ctcheck/ctcheck_test.go` (`//go:build ctcheck`), `internal/ctcheck/stats_test.go` (no tag)

**Interfaces:**
- Produces:
  - `func Run[T any](samples int, input func(class int) T, op func(T)) Result` — builds `samples` inputs up front, class 0 or 1 chosen at random per sample (crypto-quality randomness not needed: `math/rand/v2`); calibrates a batch size so one timed batch lasts ≥ 2 µs (doubling from 1, measured on class-0 input); times `batch` calls of `op` per sample with `time.Now`/`time.Since`; feeds Welch statistics.
  - `type Result struct { T float64; Samples, Batch int }` — `T` is the max |t| over the uncropped data and data cropped above the 50/75/90/95/99th percentiles of the first 1000 samples (those 1000 are warm-up and not counted), as in dudect.
  - `const Threshold = 10`.
- Timing tests in `ctcheck_test.go`, each `t.Fatalf` when `Result.T > Threshold`, logging `T`, `Samples`, `Batch`:
  - `TestNegativeControl`: `new(big.Int).Exp(base, k, mod)` with a 256-bit mod; class 0 k = 1, class 1 k random 256-bit. **Must** reach T > Threshold, else `t.Fatalf("harness insensitive on this machine: |t| = %.1f", ...)`.
  - `TestDSTU4145NewPrivateKey` (M257): class 0 d = 1, class 1 random d.
  - `TestDSTU4145SignKey`: fixed hash and a fresh random e (via `rand.Reader`) in both classes; class 0 d = 1, class 1 random d.
  - `TestDSTU4145SignNonce`: fixed random d; a reader that yields e = 1 (class 0) or random e (class 1); padded to the order length.
  - `TestKalyna128Encrypt`, `TestKalyna128Decrypt`, `TestKalyna128KeySchedule` (`NewCipher128`, 16-byte key): class 0 all-zero key/block, class 1 random.
  - `TestKupyna256`: `Sum256` of 64 bytes, class 0 zeros, class 1 random.
  - `TestGOST28147Encrypt`: DKE1, class 0 zero key/block, class 1 random.
  - Sample counts: start at 100 000 per test and tune in Task 6 so the whole package fits about 5 minutes on `ubuntu-latest`.

- [ ] **Step 1: Write `TestWelchKnownValues`** in `stats_test.go`: for two hand-written samples, e.g. {1,2,3,4,5} vs {2,4,6,8,10}, the statistic equals the value from Welch's formula computed by hand in the test comment (t = −1.897, to 3 decimals).
- [ ] **Step 2: Run** `go test ./internal/ctcheck` — Expected: FAIL (undefined).
- [ ] **Step 3: Implement** `ctcheck.go` (online Welch mean/variance per class and per crop level).
- [ ] **Step 4: Run** `go test ./internal/ctcheck` — Expected: PASS.
- [ ] **Step 5: Write the tagged timing tests** and run `go test -tags ctcheck -count=1 -timeout 30m -v ./internal/ctcheck` locally — Expected: `TestNegativeControl` passes (T > 10), all others pass (T ≤ 10). On darwin/arm64 a failure is information, not a blocker; the reference is Task 6.
- [ ] **Step 6: Confirm the test catches a real leak**: temporarily make `Curve.scalarMult` call `scalarMultVartime`, confirm that `TestDSTU4145NewPrivateKey` fails, then revert. A cache leak from a plain `table[x]` is too small to check this way.
- [ ] **Step 7: Gate and commit** "Add a dudect timing test for the secret paths".

### Task 6: Block the release on the timing test

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1:** Add `workflow_dispatch:` to `on:`. Add a job `ctcheck` (`ubuntu-latest`, checkout, setup-go from `go.mod`) running `go test -tags ctcheck -count=1 -timeout 30m -v ./internal/ctcheck`. Make job `release` `needs: ctcheck` and `if: github.event_name == 'push'` so a manual run only measures.
- [ ] **Step 2:** Validate the YAML (`actionlint` if installed; otherwise review by eye).
- [ ] **Step 3: Gate and commit** "Block the release on the timing test".
- [ ] **Step 4 (needs the user to push):** run the workflow by hand (`gh workflow run release.yml --ref main`) and read the timings; tune sample counts in Task 5 until the job takes about 5 minutes, the negative control passes and the rest stay below 10. If no count fits, drop representatives (spec: the list gives way, not the threshold). Record the observed |t| values and the job duration in the commit message of the tuning commit.

### Task 7: Documentation

**Files:**
- Modify: `README.md` (section «⚠️ Безпека», plan item), `dstu4145/dstu4145.go` package doc, `dstu4145/curve.go` (comments), `kalyna/kalyna.go` package doc, `internal/spn/spn.go` package doc

- [ ] **Step 1:** README «Безпека» (Ukrainian): which operations run in constant time (list as in Global Constraints); how it is checked (dudect test in CI on linux/amd64, blocks the release; local command `go test -tags ctcheck -count=1 -timeout 30m ./internal/ctcheck`, reliable on linux/amd64); what is out of scope (power/fault attacks, zeroization, public-data operations); keep «код не проходив аудиту» and the advice on certified КЗІ. Remove «не виконується за сталий час» and «а не для захисту бойових ключів». Plan item → `[x]`.
- [ ] **Step 2:** Godoc: `dstu4145` package doc replaces "uses math/big and is not constant-time…" with what is constant time and what is not (Verify, ParsePublicKey); `kalyna` replaces "Nothing in this package is constant-time." with "Encryption, decryption and key expansion run in constant time on 64-bit platforms."
- [ ] **Step 3: Gate and commit** "Document the constant-time guarantees".

## Self-review notes

- Spec coverage: field/ladder/mod n/key storage/random scalars → Tasks 1–3; S-boxes and `spn.Mul` → Task 4; GOST → Task 4; dudect with negative control → Task 5; release blocking + manual run → Task 6; README/godoc → Task 7. GCM/CMAC/compare already constant time: checked in review only, no task.
- Order: 1 → 3 → 2 → 4 → 5 → 6 → 7.
