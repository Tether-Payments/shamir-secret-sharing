# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue, using GitHub's [private vulnerability reporting](https://github.com/lydianpay/shamir-secret-sharing/security/advisories/new)
for this repository. We aim to acknowledge reports within a few business days.

## Security model

This package implements Shamir's Secret Sharing to provide **confidentiality** of
a secret split across shares:

- Any `threshold` distinct shares reconstruct the secret; any fewer reveal
  nothing about it (information-theoretic secrecy).
- Secret coefficients are generated with `crypto/rand`.

### What it does NOT provide

- **Authentication / integrity by default.** Shares are malleable and
  unauthenticated. `WithIntegrity()` adds a *keyless* SHA-256 tag that detects
  accidental corruption or insufficient shares — not deliberate forgery. For
  tamper protection against an active attacker, wrap the secret in an AEAD or
  keyed MAC before splitting.
- **Guaranteed constant-time execution.** Field arithmetic is implemented
  without secret-dependent branches or table lookups to reduce cache-timing
  exposure, but the Go compiler and underlying hardware do not guarantee
  constant-time behavior. Do not rely on it in environments that require verified
  constant-time guarantees without further review.
- **Memory hygiene.** Secret material is not zeroized after use.

### Using it safely

- Provide exactly `threshold` distinct shares to `Reconstruct`; fewer returns a
  wrong secret with no error (use `WithIntegrity()` to get an error instead).
- Store and transmit shares separately.
- Do not modify the field arithmetic or polynomial generation without
  corresponding cryptographic review and tests.
