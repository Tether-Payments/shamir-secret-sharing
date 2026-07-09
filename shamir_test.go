package shamir

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestGenerateShares(t *testing.T) {
	secret := []byte("Yo Cuz!")
	numberOfShares := []int{4, 6, 8}
	thresholds := []int{2, 3, 6}

	for idx, cnt := range numberOfShares {
		shares, err := GenerateShares(secret, cnt, thresholds[idx])
		if err != nil {
			t.Error(err)
		}

		// Check for the correct number of shares
		if len(shares) != cnt {
			t.Errorf("Expected %d shares, got %d", cnt, len(shares))
		}

		// Check the length of each share for correct length
		for _, share := range shares {
			if len(share) != len(secret)+1 {
				t.Errorf("Expected %d shares, got %d", len(secret)+1, len(shares))
			}
		}
	}

	// Negative Tests
	_, err := GenerateShares([]byte{}, 6, 3)
	if err == nil {
		t.Error("Expected error when using an empty secret")
	}

	_, err = GenerateShares(secret, 4, 6)
	if err == nil {
		t.Error("Expected error when calculating fewer shares than the threshold")
	}

	_, err = GenerateShares(secret, 381, 6)
	if err == nil {
		t.Error("Expected error when calculating more than 255 shares")
	}

	_, err = GenerateShares(secret, 6, 1)
	if err == nil {
		t.Error("Expected error when using a threshold less than 2")
	}

	_, err = GenerateShares(secret, 6, 381)
	if err == nil {
		t.Error("Expected error when using a threshold greater than 255")
	} else if !strings.Contains(err.Error(), "threshold") {
		t.Errorf("Expected threshold error when threshold > 255, got: %v", err)
	}
}

func TestReconstructShares(t *testing.T) {

	secrets := [][]byte{
		[]byte("Yo Cuz!"),
		[]byte("1632c1ee-8a67-40c3-92a2-8404f100e15f"),
		[]byte("mmdjphbfkdjkxpowjumccoyivysdfkxsgzbvdlxfllzvszggfozlwsyryggastbpvxdmetsazvtapyferrodlerplldmdyccivrx" +
			"wtxmvlivnuaniqyrfykdwzebrflqixgdmpzgdmuxmdwopvvxunjxdbwxizhkpuudamugbglwyxdfdlpyjxhuraolmrpafvivinthnaz" +
			"mwarajcvxlwqptwrrfpoxcuynrukymsmbcovjtdongfyhlzzdxuusgkgaourfaysvmlgmusvcmpmyclbaccnrgtgmdcmoomfhajmdsn" +
			"wepalqemmddywlviolhobzsndwfwpijwuldgeedwvyoxamtjbgbkxeuvrvdkhaolynrvpbyxmdvzvbguqlmanovgzlsvokgzcpabmsa" +
			"ikzfofmgmvnfekacstqepwrnnrzlkmumopcmuygukvyamuvgouzktfvvgqpzjbchhyeokafdvjjwzbjoxffoqwjstmjwzcnsvfxxehe"),
	}
	numberOfShares := []int{4, 6, 8}
	thresholds := []int{2, 3, 6}

	for idx, secret := range secrets {
		shares, err := GenerateShares(secret, numberOfShares[idx], thresholds[idx])
		if err != nil {
			t.Error(err)
		}

		// Randomize the shares
		rand.Shuffle(len(shares), func(i, j int) {
			shares[i], shares[j] = shares[j], shares[i]
		})

		reconstructedSecret, err := Reconstruct(shares[:numberOfShares[idx]])
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(reconstructedSecret, secret) {
			t.Errorf("Expected secret %s, got %s", secret, reconstructedSecret)
		}
	}

	// Negative Tests
	badShares := [][]byte{{3}}
	_, err := Reconstruct(badShares)
	if err == nil {
		t.Error("Expected error when passing fewer than 2 shares")
	}

	badShares = [][]byte{{3}, {4}, {5}}
	_, err = Reconstruct(badShares)
	if err == nil {
		t.Error("Expected error when share length is less than 2")
	}

	badShares = [][]byte{{1, 2, 3, 4}, {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5, 6}}
	_, err = Reconstruct(badShares)
	if err == nil {
		t.Error("Expected error when share length is not all the same")
	}

	badShares = [][]byte{{1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5}}
	_, err = Reconstruct(badShares)
	if err == nil {
		t.Error("Expected error when shares collide (force denominator to be 0 for interpolation)")
	}
}

func TestIntegrityRoundTrip(t *testing.T) {
	secret := []byte("integrity secret")
	shares, err := GenerateShares(secret, 5, 3, WithIntegrity())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Reconstruct(shares[:3], WithIntegrity())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("got %q, want %q", got, secret)
	}
}

func TestIntegrityDetectsInsufficientShares(t *testing.T) {
	secret := []byte("integrity secret")
	shares, _ := GenerateShares(secret, 5, 3, WithIntegrity())
	// Two shares for a threshold-3 secret: the plain path silently returns
	// garbage; with integrity it must error instead.
	if _, err := Reconstruct(shares[:2], WithIntegrity()); err == nil {
		t.Fatal("expected error for insufficient shares with integrity")
	}
}

func TestIntegrityDetectsCorruption(t *testing.T) {
	secret := []byte("integrity secret")
	shares, _ := GenerateShares(secret, 5, 3, WithIntegrity())
	shares[0][0] ^= 0xff // flip a y-value
	if _, err := Reconstruct(shares[:3], WithIntegrity()); err == nil {
		t.Fatal("expected error for corrupted share with integrity")
	}
}

func TestIntegrityDefaultOffUnchanged(t *testing.T) {
	// Shares made without the option still reconstruct via the plain call.
	secret := []byte("plain secret")
	shares, _ := GenerateShares(secret, 5, 3)
	got, err := Reconstruct(shares[:3])
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("plain path changed: got %q, err %v", got, err)
	}
}

func TestReconstructRejectsZeroXCoordinate(t *testing.T) {
	// A share whose final byte (x-coordinate) is 0 must be rejected: at x=0 the
	// polynomial evaluates to the secret byte itself.
	shares := [][]byte{{0x12, 0x00}, {0x34, 0x05}}
	if _, err := Reconstruct(shares); err == nil {
		t.Fatal("expected error for a share with x-coordinate 0")
	}
}

func TestReconstructIntegrityTooShort(t *testing.T) {
	// With integrity checking requested, shares whose payload is too short to
	// contain the appended tag must be rejected.
	shares, err := GenerateShares([]byte("hi"), 3, 2) // 2-byte payload, no tag
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reconstruct(shares[:2], WithIntegrity()); err == nil {
		t.Fatal("expected error when shares are too short to contain an integrity tag")
	}
}

func TestGenerateSharesRandFailure(t *testing.T) {
	// GenerateShares must fail closed (return an error) when the RNG fails,
	// never emit a weak share set.
	orig := randRead
	defer func() { randRead = orig }()
	randRead = func([]byte) (int, error) { return 0, errors.New("rng failure") }

	if _, err := GenerateShares([]byte("secret"), 5, 3); err == nil {
		t.Fatal("expected an error when the RNG fails")
	}
}
