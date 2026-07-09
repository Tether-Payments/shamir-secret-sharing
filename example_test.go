package shamir_test

import (
	"fmt"
	"log"

	"github.com/lydianpay/shamir-secret-sharing"
)

// Split a secret into 5 shares and reconstruct it from any 3.
func ExampleGenerateShares() {
	secret := []byte("my secret")

	shares, err := shamir.GenerateShares(secret, 5, 3)
	if err != nil {
		log.Fatal(err)
	}

	recovered, err := shamir.Reconstruct(shares[:3])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", recovered)
	// Output: my secret
}

// WithIntegrity lets Reconstruct detect insufficient or corrupted shares instead
// of silently returning a wrong secret. Pass it to both calls.
func ExampleWithIntegrity() {
	secret := []byte("my secret")

	shares, err := shamir.GenerateShares(secret, 5, 3, shamir.WithIntegrity())
	if err != nil {
		log.Fatal(err)
	}

	// Too few shares: reported as an error rather than returning garbage.
	if _, err := shamir.Reconstruct(shares[:2], shamir.WithIntegrity()); err != nil {
		fmt.Println("2 shares:", err)
	}

	recovered, err := shamir.Reconstruct(shares[:3], shamir.WithIntegrity())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("3 shares: %s\n", recovered)

	// Output:
	// 2 shares: invalid or insufficient shares
	// 3 shares: my secret
}
