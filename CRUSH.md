# CRUSH Guidelines

## Build, Test & Lint Commands
- **Build:** Run `go build ./...` to compile the project.
- **Test (all):** Run `go test ./...` to execute all tests.
- **Test (single):** Run `go test -run <TestName> ./...` to execute a specific test.
- **Lint:** Run `golangci-lint run` (ensure [golangci-lint](https://golangci-lint.run/) is installed) for code quality checks.

## Code Style Guidelines (Golang)
- **Imports:** Group standard library, external packages, and project packages separately; order them alphabetically within groups.
- **Formatting:** Use `gofumpt` for code formatting (`gofumpt -s -w .`).
- **Types & Naming:** Use explicit types in function signatures and variable declarations. Use CamelCase for exported names and lowerCamelCase for non-exported names.
- **Error Handling:** Always check and handle errors explicitly (e.g., `if err != nil { ... }`).
- **Testing:** Write small, focused tests (consider table-driven tests).

## Additional Guidelines
- Follow the DRY and SOLID principles.
- Always prefer using the standard library when possible.

## Repository Management
- The `.crush` directory (if used for agent configuration) should be added to `.gitignore`.
