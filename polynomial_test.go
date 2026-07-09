package shamir

import (
	"errors"
	"testing"
)

func TestGeneratePolynomial(t *testing.T) {
	thresholds := []uint8{3, 7, 41}
	intercepts := []uint8{7, 41, 230}

	for idx, threshold := range thresholds {
		intercept := intercepts[idx]

		polynomial, err := generatePolynomial(intercept, threshold)
		if err != nil {
			t.Error(err)
		}

		if len(polynomial) != int(threshold) {
			t.Errorf("Expected polynomial of length %d, but got %d", threshold, len(polynomial))
		}

		if polynomial[0] != intercept {
			t.Errorf("Expected first position to be %d, but got %d", intercept, polynomial[0])
		}
	}

}

func TestGeneratePolynomialNonZeroLeadingCoeff(t *testing.T) {
	for _, threshold := range []uint8{2, 3, 16, 255} {
		for i := 0; i < 10000; i++ {
			p, err := generatePolynomial(7, threshold)
			if err != nil {
				t.Fatal(err)
			}
			if p[threshold-1] == 0 {
				t.Fatalf("leading coefficient is zero for threshold %d", threshold)
			}
		}
	}
}

func TestGeneratePolynomialRandFailure(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	randRead = func([]byte) (int, error) { return 0, errors.New("rng failure") }

	if _, err := generatePolynomial(7, 3); err == nil {
		t.Fatal("expected an error when the RNG fails")
	}
}

func TestGeneratePolynomialResampleRandFailure(t *testing.T) {
	orig := randRead
	defer func() { randRead = orig }()
	call := 0
	randRead = func(b []byte) (int, error) {
		call++
		if call == 1 {
			// Zero-fill so the leading coefficient is 0 and the resample loop runs.
			for i := range b {
				b[i] = 0
			}
			return len(b), nil
		}
		return 0, errors.New("rng failure")
	}

	if _, err := generatePolynomial(7, 3); err == nil {
		t.Fatal("expected an error when the RNG fails during resample")
	}
}

func TestEvaluate(t *testing.T) {
	polynomials := [][]byte{
		{7, 153, 159},
		{41, 135, 212, 229, 29, 159, 230},
		{230, 42, 98, 94, 254, 244, 35, 24, 166, 190, 82, 234, 166, 11, 161, 56, 17, 109, 73, 112, 236, 221, 141, 190, 53, 69, 117, 8, 67, 88, 168, 181, 223, 10, 184, 100, 210, 74, 85, 180, 2},
	}
	xValues := []uint8{23, 16, 139}
	yValues := []uint8{77, 170, 66}

	for idx, polynomial := range polynomials {
		yValue := evaluate(polynomial, xValues[idx])
		if yValue != yValues[idx] {
			t.Errorf("Expected yValue of %d, but got %d", yValues[idx], yValue)
		}
	}
}

func TestInterpolate(t *testing.T) {
	xValue := []byte{222, 32, 140}
	yValues := [][]byte{
		{143, 37, 238},
		{180, 90, 127},
		{4, 62, 159},
	}
	secrets := []byte{89, 111, 32}

	for idx, yValue := range yValues {
		secret, err := interpolate(xValue, yValue)
		if err != nil {
			t.Error(err)
		}
		if secret != secrets[idx] {
			t.Errorf("Expected secret of %d, but got %d", secrets[idx], secret)
		}
	}

	_, err := interpolate([]byte{41, 41}, []byte{7, 7})
	if err == nil {
		t.Errorf("Expected error when interpolating an x sample denominator of 0")
	}

}
