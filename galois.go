package shamir

import (
	"errors"
)

// addGF adds two numbers in Galois Field (2^8)
func addGF(a, b uint8) uint8 {
	return a ^ b
}

// multiplyGF multiplies two numbers in a Galois Field (2^8).
//
// It uses a branchless carry-less multiply with reduction modulo the AES
// polynomial x^8 + x^4 + x^3 + x + 1 (0x11b), so it has no data-dependent
// branches and no secret-indexed table lookups.
func multiplyGF(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		// Add a into the product when the low bit of b is set; the mask is
		// 0xff when (b&1)==1 and 0x00 otherwise.
		p ^= a & -(b & 1)
		// Multiply a by x (shift left) and reduce by 0x1b on overflow.
		a = (a << 1) ^ (0x1b & -(a >> 7))
		b >>= 1
	}
	return p
}

// inverseGF returns the multiplicative inverse of a in GF(2^8), computed as
// a^254 (since a^255 == 1 for a != 0). inverseGF(0) returns 0.
func inverseGF(a uint8) uint8 {
	result := uint8(1)
	base := a
	// 254 == 0b11111110: multiply for set exponent bits (1..7), square each step.
	for i := 0; i < 8; i++ {
		if (254>>i)&1 == 1 {
			result = multiplyGF(result, base)
		}
		base = multiplyGF(base, base)
	}
	return result
}

// divideGF divides two numbers in a Galois Field (2^8)
func divideGF(a, b uint8) (uint8, error) {
	if b == 0 {
		return 0, errors.New("denominator cannot be 0")
	}

	if a == 0 {
		return 0, nil
	}

	return multiplyGF(a, inverseGF(b)), nil
}
