// Package shamir implements Shamir's Secret Sharing over GF(2^8).
//
// A secret is split into n shares such that any threshold (k) of them
// reconstruct it, while any k-1 shares reveal nothing about it. Each byte of the
// secret is shared independently with its own random degree k-1 polynomial.
//
// Basic usage:
//
//	shares, err := shamir.GenerateShares(secret, 5, 3)
//	// ...
//	secret, err := shamir.Reconstruct(shares[:3])
//
// Share format: each share is len(secret)+1 bytes — the y-values followed by a
// single non-zero x-coordinate byte. Treat shares as opaque and store them
// separately.
//
// Reconstruction requires exactly threshold distinct shares. Supplying fewer
// (but at least two) returns a wrong secret with no error, because the scheme
// reveals nothing below the threshold. Pass [WithIntegrity] to both
// GenerateShares and Reconstruct to detect insufficient or corrupted shares via
// a keyless SHA-256 tag; it catches accidents, not deliberate forgery.
//
// Security: this package provides confidentiality, not authentication. Its field
// arithmetic avoids secret-dependent branches and table lookups to reduce
// cache-timing exposure, though the Go compiler does not guarantee constant-time
// execution. Secret material is not zeroized. See SECURITY.md.
package shamir
