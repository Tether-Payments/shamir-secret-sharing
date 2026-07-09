# Contributing

Thanks for your interest in improving this library.

## Development

- Requires Go (see the version in `go.mod`).
- This package has **zero external dependencies** — please keep it standard-library only.

Before opening a pull request, make sure these all pass:

```sh
go build ./...
go test -race ./...
go vet ./...
golangci-lint run ./...
```

## Guidelines

- Add or update tests for any behavior change.
- Changes to the cryptographic core (`galois.go`, `polynomial.go`) must preserve
  the field and secret-sharing invariants and be covered by tests.
- Keep the code `gofmt`-clean.
