# AGENTS.md

Guidance for AI agents and human contributors working in this repository. If
you change code here, read the **Security invariants** section first — several of
them are not obvious from the source and silently break confidentiality or
correctness if violated.

## What this is

A dependency-free Go implementation of Shamir's Secret Sharing.

- Module: `github.com/lydianpay/shamir-secret-sharing`, package `shamir`.
- **Zero external dependencies — standard library only.** This is a hard
  constraint; do not add third-party modules.

## Layout

| File | Responsibility |
|------|----------------|
| `galois.go` | GF(2⁸) arithmetic (`addGF`, `multiplyGF`, `divideGF`) via a branchless carry-less multiply and an `a²⁵⁴` inverse. The field uses the AES reduction polynomial `0x11b`. |
| `polynomial.go` | `generatePolynomial` (random polynomial with a fixed intercept), `evaluate` (Horner's method), `interpolate` (Lagrange interpolation at x=0). |
| `shamir.go` | Public API: `GenerateShares`, `Reconstruct`, and the `WithIntegrity` option. |
| `*_test.go` | Unit, known-answer, negative, and property/round-trip tests. |

## Public API

```go
func GenerateShares(secret []byte, numberOfShares, threshold int, opts ...Option) ([][]byte, error)
func Reconstruct(shares [][]byte, opts ...Option) ([]byte, error)
func WithIntegrity() Option
```

Argument constraints (enforced by `GenerateShares`):
- `threshold` in `[2, 255]`
- `numberOfShares` in `[threshold, 255]`
- `secret` non-empty

### Share format

Each share is `len(payload)+1` bytes:
- bytes `[0:len(payload)]` — one y-value per payload byte,
- final byte — the share's x-coordinate, always in `[1, 255]`.

`payload` is the `secret`, or `secret ‖ tag` when `WithIntegrity()` is used,
where `tag` is the first 8 bytes of `SHA-256(secret)`.

## Security invariants

Read these before touching `galois.go`, `polynomial.go`, or the validation in
`shamir.go`.

- **Supply exactly `threshold` distinct shares to `Reconstruct`.** Providing
  fewer than `threshold` (but ≥ 2) returns a *wrong* secret with **no error** —
  this is intentional: Shamir reveals nothing below the threshold, and reporting
  the required count would leak it. Use `WithIntegrity()` if you want a generic
  error instead of silent garbage.
- **x-coordinates must be non-zero and distinct.** A share with x-coordinate `0`
  equals the secret byte itself (`evaluate(poly, 0) == intercept`); duplicate
  x-coordinates make interpolation ill-defined. `Reconstruct` rejects both.
  `GenerateShares` never emits `x = 0` (it maps `1..255`).
- **`WithIntegrity()` must be passed to BOTH `GenerateShares` and `Reconstruct`,**
  and shares are not interchangeable between the two modes. The tag is a
  *keyless* truncated SHA-256: it detects insufficient or corrupted shares
  (accidents), **not** deliberate forgery. For authenticated integrity, wrap the
  secret in an AEAD or keyed MAC before splitting.
- **Each secret byte gets its own random polynomial of degree `threshold-1`
  with a non-zero leading coefficient.** The non-zero leading coefficient is
  required so the effective degree — and thus the k-of-n threshold — actually
  holds. `generatePolynomial` enforces this.
- **This library provides confidentiality, not authentication.** GF operations
  avoid secret-dependent branches and table lookups to reduce cache-timing
  exposure, but the Go compiler does not guarantee constant-time execution, and
  secrets are not zeroized. Do not rely on verified constant-time behavior
  without further review.
- Coefficients come from `crypto/rand`. x-coordinates come from `math/rand/v2`,
  which is acceptable because x-coordinates are public and only need to be
  distinct and non-zero — do not "downgrade" the coefficient randomness to match.

## Commands

```sh
go build ./...
go test ./...                              # unit + property tests
go test -race -coverprofile=coverage.out ./...
go vet ./...
golangci-lint run ./...                    # must be clean (golangci-lint v2)
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

## Conventions for changes

- Keep the standard-library-only constraint.
- Keep `gofmt`, `go vet`, and `golangci-lint run` clean, and add or update tests
  for any behavior change; run `go test -race ./...` before proposing changes.
- Any change to `galois.go` or `polynomial.go` must preserve the field/algebra
  invariants and be covered by known-answer and/or property tests (e.g.
  split → reconstruct round-trips, field-axiom checks).
- Do not weaken the security invariants above without an explicit, documented
  decision.
