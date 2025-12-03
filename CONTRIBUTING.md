# Contributing to cbom-generator

Thank you for your interest in contributing to cbom-generator! This document provides guidelines and instructions for contributing.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Making Changes](#making-changes)
5. [Testing](#testing)
6. [Submitting Changes](#submitting-changes)
7. [Coding Standards](#coding-standards)
8. [Plugin Contributions](#plugin-contributions)
9. [Documentation](#documentation)
10. [Getting Help](#getting-help)
11. [License](#license)

## Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors. Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Linux system (Ubuntu 20.04+, RHEL 8+, or equivalent)
- CMake 3.16+
- GCC 10+ or Clang 11+
- OpenSSL 3.0+ (3.5+ recommended for PQC support)
- json-c 0.15+
- libcurl (latest)
- libyaml 0.2.2+
- jansson 2.13+
- ncurses
- SQLite 3
- Git

### Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/cbom-generator.git
cd cbom-generator

# Add upstream remote
git remote add upstream https://github.com/cipheriq/cbom-generator.git
```

## Development Setup

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install cmake gcc libssl-dev libjson-c-dev libcurl4-openssl-dev
sudo apt install libyaml-dev libjansson-dev libncurses-dev libsqlite3-dev
sudo apt install valgrind cppcheck  # For testing and static analysis
```

**RHEL/Fedora:**
```bash
sudo dnf install cmake gcc openssl-devel json-c-devel libcurl-devel
sudo dnf install libyaml-devel jansson-devel ncurses-devel sqlite-devel
sudo dnf install valgrind cppcheck
```

### Build the Project

```bash
# Configure release build
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build

# For debug builds (recommended during development)
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug
```

### Verify Your Setup

```bash
# Run test suite
cd build && ctest

# Test basic functionality
./build/cbom-generator --help

# Run a scan
./build/cbom-generator -o test.json --no-personal-data --no-network /usr/bin
```

## Making Changes

### Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create a feature branch
git checkout -b feature/your-feature-name
```

### Branch Naming Conventions

- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions or modifications

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of the change (if needed).

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Build system or auxiliary tool changes

**Examples:**
```
feat(scanner): add support for Ed448 key detection

Add Ed448 curve detection to the key scanner module.
Includes support for both PEM and DER formats.

Fixes #42
```

```
fix(cache): resolve memory leak in SQLite cleanup

Ensure prepared statements are finalized before
closing the database connection.

Fixes #56
```

## Testing

### Run All Tests

```bash
cd build && ctest
```

### Run Specific Tests

```bash
# Run a specific test suite
cd build && ctest -R test_certificate_scanner

# Run with verbose output
cd build && ctest -V
```

### Add New Tests

- Add test files to `tests/` directory
- Follow existing naming pattern: `test_<component>.c`
- Use the project's test framework (see existing tests for patterns)
- Ensure tests are deterministic and do not depend on external state

**Test Requirements:**
- Unit tests for all new functions
- Integration tests for cross-component features
- Validate actual CBOM output when applicable
- No regressions in existing tests

### Memory Leak Testing

```bash
# Build debug version first
cmake -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug

# Run with valgrind
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
    --track-origins=yes ./build-debug/cbom-generator \
    -o test.json --no-personal-data --no-network /usr/bin 2>&1 | tail -50
```

### Static Analysis

```bash
cd build
make static-analysis    # Clang static analyzer + cppcheck
make check-orphan-code  # Detect unused code
make check-all          # Run all quality checks
```

### Debug Segmentation Faults

```bash
gdb --batch --ex run --ex bt --ex quit --args \
    ./build-debug/cbom-generator -o test.json --no-personal-data /usr/bin
```

## Submitting Changes

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] All tests pass (`cd build && ctest`)
- [ ] No memory leaks (verified with valgrind)
- [ ] Static analysis passes (`make static-analysis`)
- [ ] Documentation updated (if applicable)
- [ ] Commit messages follow conventions
- [ ] Branch is up to date with upstream main
- [ ] New files include required license header

### Create Pull Request

1. Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Go to GitHub and create a Pull Request

3. Fill out the PR template:
   - Description of changes
   - Related issues
   - Testing performed
   - CycloneDX output validation (if scanner changes)

4. Wait for review and address feedback

### PR Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged

## Coding Standards

### General Guidelines

- **C11 standard compliance** (no GNU extensions)
- **Compile with `-Wall -Wextra -Werror`** (strict warnings)
- **No memory leaks** (verified with valgrind)
- **Bounds checking** on all array access
- **Thread safety** for all shared resources (use POSIX mutexes)

### Memory Management (CRITICAL)

**NEVER use raw `malloc`/`free` in this codebase.**

All memory allocation MUST use the secure memory functions from `src/secure_memory.c`:

```c
#include "secure_memory.h"

// Correct usage
void *buffer = secure_alloc(size);
if (!buffer) {
    return -ENOMEM;
}
// ... use buffer ...
secure_free(buffer);

// For sensitive data, zero before freeing
secure_zero(buffer, size);
secure_free(buffer);
```

**Why?** The secure memory functions:
- Zero memory on allocation and deallocation
- Prevent sensitive data leakage
- Integrate with the project's resource tracking

Mixing `malloc`/`free` with secure memory functions **will cause crashes**.

### License Header (Required)

All new `.c` and `.h` files MUST include this header at the top, before any `#include` directives:

```c
// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Copyright (c) 2025 Graziano Labs Corp.
 *
 * This file is part of cbom-generator.
 *
 * cbom-generator is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * For commercial licensing options, contact: sales@cipheriq.io
 */
```

### Code Style

**Indentation:**
- Use 4 spaces (no tabs)
- Indent case labels in switch statements

**Naming:**
- Functions: `snake_case()`
- Variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Types: `snake_case_t`
- Structs: `struct snake_case`

**Example:**
```c
#define MAX_BUFFER_SIZE 4096

typedef struct {
    int field_one;
    char *field_two;
} my_struct_t;

static int helper_function(const char *input) {
    if (!input) {
        return -EINVAL;
    }
    // Implementation
    return 0;
}

int public_function(my_struct_t *data) {
    if (!data) {
        return -EINVAL;
    }

    int result = helper_function(data->field_two);
    if (result < 0) {
        return result;
    }

    return 0;
}
```

### Error Handling

- Check all return values
- Use negative errno values for errors
- Provide clear error messages
- Clean up resources in error paths

**Example:**
```c
int process_data(const char *input) {
    char *buffer = NULL;
    int fd = -1;
    int ret = 0;

    // Validate input
    if (!input) {
        return -EINVAL;
    }

    // Allocate with secure memory
    buffer = secure_alloc(BUFFER_SIZE);
    if (!buffer) {
        ret = -ENOMEM;
        goto cleanup;
    }

    // Open file
    fd = open(input, O_RDONLY);
    if (fd < 0) {
        ret = -errno;
        goto cleanup;
    }

    // Process...

cleanup:
    if (buffer) {
        secure_free(buffer);
    }
    if (fd >= 0) {
        close(fd);
    }
    return ret;
}
```

## Plugin Contributions

The project supports YAML-based service discovery plugins. For details on creating or modifying plugins, see:

- Plugin development guide in CipherIQ **[documentation](https://www.cipheriq.io)** website
- `plugins/` - Existing plugins for reference

## Documentation

Full CipherIQ **[documentation](https://www.cipheriq.io)** website with comprehensive usage guide and CLI reference
### Update Documentation

When making changes, update relevant documentation:

- **README.md** - For user-facing changes
- **Code comments** - For implementation details

## Getting Help


### Contact

- **GitHub Issues:** For bug reports, feature requests, and questions
- **Email:** support@cipheriq.io

## License

By contributing to cbom-generator, you agree that your contributions will be licensed under the GPL-3.0-or-later license.

For commercial licensing inquiries, contact: sales@cipheriq.io

---

Thank you for contributing to cbom-generator!
