# Shamir's Secret Sharing Algorithm
---
<div align="center">

[![Go Report Card](https://goreportcard.com/badge/lydianpay/shamir-secret-sharing)](https://goreportcard.com/report/lydianpay/shamir-secret-sharing)
[![Code Coverage](https://qlty.sh/gh/lydianpay/projects/shamir-secret-sharing/coverage.svg)](https://qlty.sh/gh/lydianpay/projects/shamir-secret-sharing)
[![Maintainability](https://qlty.sh/gh/lydianpay/projects/shamir-secret-sharing/maintainability.svg)](https://qlty.sh/gh/lydianpay/projects/shamir-secret-sharing)
[![CodeQL](https://github.com/lydianpay/shamir-secret-sharing/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lydianpay/shamir-secret-sharing/actions/workflows/github-code-scanning/codeql)

</div>

Written in Go ('Golang' for search engines) with zero external dependencies, this package implements
[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing). Shamir's Secret Sharing (SSS) is used to distribute a secret amongst a group, wherein a
quorum must be achieved to reconstruct the original secret. No individual shareholder can recreate the secret alone.

Shamir's Secret Sharing is information-theoretically secure and perfectly secure since no information about the secret
is revealed without the quorum (threshold) of shares being achieved.

Using this package, you can split a secret into <i>n</i> shares, which can only be reconstructed if the threshold of
shares you choose is met.

---

## Installation & Usage

1. Once confirming you have [Go](https://go.dev/doc/install) installed, the command below will add
`shamir` as a dependency to your Go program.
```shell
go get github.com/lydianpay/shamir-secret-sharing
```
2. Import the package into your code
```go
package main

import (
    "github.com/lydianpay/shamir-secret-sharing"
)
```
3. Create n number of shares
```go
shares, err := shamir.GenerateShares(secret, numberOfShares, threshold)
```

4. Reconstruct the original secret
```go
secret, err := shamir.Reconstruct(shares)
```

## Example

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	shamir "github.com/lydianpay/shamir-secret-sharing"
)

func main() {
	secret := []byte("my super secret")        // Replace with your secret
	numberOfShares := 6                        // Number of shares to be created
	threshold := 3                             // Minimum number of shares required to reconstruct the secret

	shares, err := shamir.GenerateShares(secret, numberOfShares, threshold)
	if err != nil {
		log.Fatal(err)
	}

	// If you want to view the shares in base64 encoding
	for idx, share := range shares {
		shareValue := base64.StdEncoding.EncodeToString(share)
		fmt.Println(fmt.Sprintf("Share %d: %s", idx, shareValue))
	}
	
	reconstructedSecret, err := shamir.Reconstruct(shares[:3])
	if err != nil {
		log.Fatal(err)
    }
	
	fmt.Printf("Reconstructed Secret: %s\n", reconstructedSecret)
}
```
