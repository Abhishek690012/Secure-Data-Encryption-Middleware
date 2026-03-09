# Secure Data Encryption Middleware

A modular **C++ cryptographic middleware** designed to provide a safe interface for authenticated encryption while preventing common cryptographic misuse.

The project introduces a layered architecture separating:

* memory safety
* key management
* encryption primitives
* public API usage

This structure ensures that applications interact with a **simple and safe cryptographic interface** while sensitive operations remain internally controlled.

---

# Features

* Authenticated Encryption (AEAD)
* Context-based encryption isolation
* Secure memory buffers with automatic zeroization
* Deterministic key derivation
* Tamper detection tests
* Modular layered design

---

# Project Structure

```
secure/
│
├── demo/
│   └── dedmo.cpp
│
├── include/
│   ├── api/
│   ├── context/
│   ├── crypto/
│   ├── keys/
│   └── util/
│
├── src/
│   ├── api/
│   ├── context/
│   ├── crypto/
│   ├── keys/
│   └── util/
│
├── tests/
│   └── basic_flow_test.cpp
│
├── run.sh
├── test_runner
└── demo_app
```

Directory responsibilities:

| Directory | Purpose                                  |
| --------- | ---------------------------------------- |
| util      | Secure buffers and zeroization utilities |
| context   | Encryption context separation            |
| keys      | Root key handling and key derivation     |
| crypto    | AEAD encryption implementation           |
| api       | Public middleware interface              |
| tests     | Security validation tests                |
| demo      | Example middleware usage                 |

---

# Requirements

The project has **very minimal dependencies**.

Required software:

* Linux environment
* GCC / G++ compiler
* C++20 support
* Bash shell

Example installation on Fedora:

```
sudo dnf install gcc-c++
```

---

# Building and Running

The project includes a helper script to automate compilation and execution.

Make the script executable:

```
chmod +x run.sh
```

Run the project:

```
./run.sh
```

This will automatically:

1. Compile the middleware
2. Run security tests
3. Build the demo application
4. Execute the demo

---

# Security Tests

The test suite validates critical security properties such as:

* Encryption / Decryption roundtrip
* Ciphertext tampering detection
* Authentication tag verification
* Context isolation
* Associated data mismatch protection

Example output:

```
Running crypto middleware tests

[PASS] Encryption-Decryption roundtrip
[PASS] Ciphertext tampering detected
[PASS] Tag tampering detected
[PASS] Context separation enforced
[PASS] Associated data integrity enforced
```

---

# Demo Application

The demo program shows how an application can interact with the middleware API.

Typical usage pattern:

```
CryptoService service(root_key);

auto ciphertext = service.encrypt(
    "session_context",
    plaintext,
    associated_data
);

auto plaintext = service.decrypt(
    "session_context",
    ciphertext,
    associated_data
);
```

The middleware internally handles:

* key derivation
* nonce management
* authenticated encryption
* secure memory handling

---

# Using the Middleware in Other Applications

To integrate this middleware:

1. Include the API header

```
#include "api/crypto_service.hpp"
```

2. Compile your application with the middleware source files.

Example:

```
g++ app.cpp \
-Iinclude \
src/util/*.cpp \
src/context/*.cpp \
src/keys/*.cpp \
src/crypto/*.cpp \
src/api/*.cpp
```

---

# Security Design Notes

This middleware prevents common cryptographic mistakes by:

* preventing direct key reuse
* enforcing context separation
* verifying authentication tags
* isolating cryptographic primitives
* automatically zeroizing sensitive buffers

The design encourages **safe-by-default cryptographic usage**.

---

# License

This project is intended for educational and research purposes.
