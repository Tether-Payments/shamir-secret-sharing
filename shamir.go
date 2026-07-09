package shamir

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
)

// integrityTagLen is the number of leading SHA-256 bytes appended to the secret
// when integrity checking is enabled. 8 bytes gives a ~2^-64 chance that an
// insufficient or corrupted reconstruction passes undetected.
const integrityTagLen = 8

// config holds optional behavior toggled via Option values.
type config struct {
	integrity bool
}

// Option customizes GenerateShares and Reconstruct.
type Option func(*config)

// WithIntegrity appends a truncated SHA-256 tag to the secret before splitting
// and verifies it on reconstruction, so Reconstruct can detect insufficient or
// corrupted shares and return a generic error instead of silently returning a
// wrong secret. It does not reveal the threshold and does not defend against a
// deliberate forger (the tag is keyless) — it catches accidental misuse and
// corruption. Off by default; the same option must be passed to both
// GenerateShares and Reconstruct, and shares are not interchangeable between the
// two modes.
func WithIntegrity() Option {
	return func(c *config) { c.integrity = true }
}

// GenerateShares takes in a secret and splits it into n shares, not greater than 255 shares
// Threshold is the minimum number of shares required to reconstruct the secret
func GenerateShares(secret []byte, numberOfShares, threshold int, opts ...Option) ([][]byte, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	if threshold < 2 || threshold > 255 {
		return nil, fmt.Errorf("threshold must be between 2 and 255")
	}

	if numberOfShares < threshold || numberOfShares > 255 {
		return nil, fmt.Errorf("number of shares must be between the threshold (%d) and 255", threshold)
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("secret must not be empty")
	}

	// When integrity checking is enabled, append a truncated SHA-256 tag to the
	// secret so Reconstruct can detect insufficient or corrupted shares.
	payload := secret
	if cfg.integrity {
		sum := sha256.Sum256(secret)
		payload = append(append(make([]byte, 0, len(secret)+integrityTagLen), secret...), sum[:integrityTagLen]...)
	}

	// Generate random list of x coordinates
	xCoordinates := rand.Perm(255)

	// Initialize the share output with a random x-coordinate as the final byte
	shares := make([][]byte, numberOfShares)
	for idx := range shares {
		shares[idx] = make([]byte, len(payload)+1)
		shares[idx][len(payload)] = uint8(xCoordinates[idx]) + 1
	}

	// Iterate over each byte of the payload to generate a random polynomial for each byte
	for idx, intercept := range payload {
		polynomial, err := generatePolynomial(intercept, uint8(threshold))
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}

		// Using the x-coordinate for each share, compute the polynomial value
		for i := 0; i < numberOfShares; i++ {
			shares[i][idx] = evaluate(polynomial, shares[i][len(payload)]) // The x-coordinate for each share
		}
	}

	return shares, nil
}

// Reconstruct This method takes n number of shares and reconstructs the original secret
func Reconstruct(shares [][]byte, opts ...Option) (secret []byte, err error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	if len(shares) < 2 {
		return nil, fmt.Errorf("minimum of two shares required to reconstruct a secret")
	}

	// Use the first share as the length to check against
	shareLength := len(shares[0])

	if shareLength < 2 {
		return nil, fmt.Errorf("shares must be a minimum of two bytes")
	}

	for i := 1; i < len(shares); i++ {
		if len(shares[i]) != shareLength {
			return nil, fmt.Errorf("shares must all be the same length")
		}
	}

	secret = make([]byte, shareLength-1)
	xValues := make([]uint8, len(shares))
	yValues := make([]uint8, len(shares))

	// Retrieve the x-coordinate from the end of each share
	seen := make(map[uint8]bool, len(shares))
	for i, share := range shares {
		x := share[shareLength-1]
		if x == 0 {
			return nil, fmt.Errorf("invalid share: x-coordinate must not be zero")
		}
		if seen[x] {
			return nil, fmt.Errorf("invalid shares: duplicate x-coordinate %d", x)
		}
		seen[x] = true
		xValues[i] = x
	}

	// Reconstruct each byte of the potential secret
	for idx := range secret {
		// Retrieve the y-coordinate from each share
		for i, share := range shares {
			yValues[i] = share[idx]
		}

		secret[idx], err = interpolate(xValues, yValues)
		if err != nil {
			return nil, fmt.Errorf("failed to interpolate shares: %w", err)
		}
	}

	// When integrity checking is enabled, split off the appended tag and verify
	// it. A mismatch means the shares were insufficient or corrupted; return a
	// generic error that does not disclose the threshold.
	if cfg.integrity {
		if len(secret) <= integrityTagLen {
			return nil, fmt.Errorf("shares too short to contain an integrity tag")
		}
		data := secret[:len(secret)-integrityTagLen]
		sum := sha256.Sum256(data)
		if !bytes.Equal(sum[:integrityTagLen], secret[len(secret)-integrityTagLen:]) {
			return nil, fmt.Errorf("invalid or insufficient shares")
		}
		return data, nil
	}

	return secret, nil
}
