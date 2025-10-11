# Linting Guide

This project uses golangci-lint for comprehensive code quality checks.

## Installation

golangci-lint is already installed via Homebrew:
```bash
brew install golangci-lint
```

## Running the Linter

### Check all code
```bash
golangci-lint run ./...
```

### Check specific package
```bash
golangci-lint run pkg/dnssec/
```

### Auto-fix issues where possible
```bash
golangci-lint run --fix ./...
```

## Configuration

Linting configuration is in `.golangci.yml` with the following enabled linters:

### Core Linters (Always Enabled)
- **errcheck** - Catches unchecked errors
- **govet** - Standard Go vet checks
- **staticcheck** - Advanced static analysis
- **ineffassign** - Finds ineffectual assignments
- **unused** - Finds unused code

### Security & Reliability
- **gosec** - Security vulnerability scanner (21 issues currently)
- **errcheck** - Unchecked error detection (41 issues currently)
- **errorlint** - Error wrapping best practices
- **bodyclose** - HTTP response body closure
- **noctx** - Context.Context usage

### Code Quality
- **revive** - Comprehensive style checker (34 issues currently)
- **gocritic** - Performance and style checks
- **goconst** - Repeated strings → constants
- **dupl** - Duplicate code detection
- **cyclop** - Cyclomatic complexity (max: 20)
- **gocognit** - Cognitive complexity (max: 25)

### Maintainability
- **lll** - Line length (max: 150 chars)
- **nestif** - Nested if complexity
- **maintidx** - Maintainability index

## Current Status

```
179 total issues across the codebase:
- errcheck: 41      (unchecked errors)
- revive: 34        (style issues)
- gosec: 21         (security)
- cyclop: 18        (complexity)
- gochecknoglobals: 12
- gocritic: 10
- lll: 8            (line length)
- nestif: 7
- noctx: 6
- staticcheck: 5
- Others: 17
```

## Disabled Linters

The following linters are intentionally disabled as too strict for this project:

- **err113** - Error wrapping style (79 issues)
- **godot** - Comment punctuation (432 issues)
- **paralleltest** - t.Parallel() requirement (121 issues)
- **wrapcheck** - Error wrapping strictness (18 issues)
- **godox** - TODO/FIXME detection (allowed during development)
- **varnamelen** - Variable name length rules
- **funlen** - Function length (covered by complexity linters)

## Fixing Issues

### Priority Order
1. **errcheck** - Critical: unchecked errors can cause bugs
2. **gosec** - Important: security vulnerabilities
3. **staticcheck** - Important: potential bugs
4. **revive** - Medium: code style improvements
5. **cyclop/gocognit** - Medium: reduce complexity
6. **Others** - Low: code quality improvements

### Common Fixes

**Unchecked errors (errcheck)**:
```go
// Bad
someFunc()

// Good
if err := someFunc(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

**Security issues (gosec)**:
```go
// Review each G### code and apply appropriate fixes
// Common: G104 (unchecked errors), G401 (weak crypto)
```

**Cyclomatic complexity (cyclop)**:
```go
// Refactor complex functions into smaller, focused functions
// Extract validation, error handling into separate functions
```

## Integration

### Pre-commit Hook (Optional)
```bash
# .git/hooks/pre-commit
#!/bin/sh
golangci-lint run --new-from-rev=HEAD~1
```

### CI/CD
```yaml
# GitHub Actions example
- name: golangci-lint
  uses: golangci/golangci-lint-action@v3
  with:
    version: v2.5.0
```

## Guidelines

1. **Don't disable linters** without discussion
2. **Fix incrementally** - tackle one linter at a time
3. **Document exceptions** - use `//nolint:lintername // reason` sparingly
4. **Run before committing** - `golangci-lint run ./...`
5. **Fix new issues immediately** - don't let tech debt accumulate
