package shamir

import (
	"testing"
)

func TestAddGF(t *testing.T) {

	if out := addGF(41, 41); out != 0 {
		t.Fatalf("Should be 0. Got: %v", out)
	}

	if out := addGF(41, 7); out != 46 {
		t.Fatalf("Expected 46. Got: %v", out)
	}

	if out := addGF(9, 18); out != 27 {
		t.Fatalf("Expected 27. Got: %v", out)
	}
}

func TestMultiplyGF(t *testing.T) {
	if out := multiplyGF(41, 41); out != 45 {
		t.Fatalf("Expected 45. Got: %v", out)
	}

	if out := multiplyGF(7, 7); out != 21 {
		t.Fatalf("Expected 21. Got: %v", out)
	}

	if out := multiplyGF(0, 7); out != 0 {
		t.Fatalf("Expected 0. Got: %v", out)
	}

	if out := multiplyGF(7, 0); out != 0 {
		t.Fatalf("Expected 0. Got: %v", out)
	}
}

func TestDivideGF(t *testing.T) {
	aValues := []uint8{41, 41, 7, 0}
	bValues := []uint8{41, 7, 41, 7}

	expectedValues := []uint8{1, 102, 54, 0}

	for idx, a := range aValues {
		out, err := divideGF(a, bValues[idx])
		if err != nil {
			t.Fatal(err)
		}
		if out != expectedValues[idx] {
			t.Fatalf("Expected %d. Got: %d", expectedValues[idx], out)
		}
	}

	// Negative Tests
	_, err := divideGF(7, 0)
	if err == nil {
		t.Fatal("Expected an error when the denominator is 0")
	}

	_, err = divideGF(0, 0)
	if err == nil {
		t.Fatal("Expected an error when dividing 0 by 0")
	}
}

// refMultiplyGF is a plain-branch schoolbook GF(2^8) multiply (reduction
// polynomial 0x1b). It is an independent reference for the branchless
// multiplyGF, so a masking bug in the latter is caught exhaustively.
func refMultiplyGF(a, b uint8) uint8 {
	var p uint8
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func TestMultiplyGFExhaustive(t *testing.T) {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if got, want := multiplyGF(uint8(a), uint8(b)), refMultiplyGF(uint8(a), uint8(b)); got != want {
				t.Fatalf("multiplyGF(%d, %d) = %d, want %d", a, b, got, want)
			}
		}
	}
}

func TestDivideGFInverseExhaustive(t *testing.T) {
	for b := 1; b < 256; b++ {
		if got := multiplyGF(uint8(b), inverseGF(uint8(b))); got != 1 {
			t.Fatalf("inverseGF(%d) wrong: b * inv = %d, want 1", b, got)
		}
		for a := 0; a < 256; a++ {
			q, err := divideGF(uint8(a), uint8(b))
			if err != nil {
				t.Fatalf("divideGF(%d, %d) unexpected error: %v", a, b, err)
			}
			if got := multiplyGF(q, uint8(b)); got != uint8(a) {
				t.Fatalf("divideGF(%d, %d) = %d; (a/b)*b = %d, want %d", a, b, q, got, a)
			}
		}
	}

	for a := 0; a < 256; a++ {
		if _, err := divideGF(uint8(a), 0); err == nil {
			t.Fatalf("divideGF(%d, 0) expected an error", a)
		}
	}
}
