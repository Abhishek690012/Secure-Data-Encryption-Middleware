#pragma once

#include <cstddef>
#include <cstdint>

// Forward declarations
namespace keys {
class RootKey;
}

namespace context {
class Context;
}

namespace util {
class SecureBuffer;
}

namespace crypto {
enum class AeadResult;
}

namespace api {

/**
 * Result codes for high-level cryptographic operations.
 */
enum class CryptoResult {
    Success,
    AuthenticationFailed,
    InvalidInput
};

/**
 * High-level cryptographic service for context-bound encryption and decryption.
 * Orchestrates RootKey, KeyDerivation, and AEAD while hiding crypto complexities.
 */
class CryptoService {
public:
    /**
     * Construct the service bound to a specific root key.
     * The root key is stored by reference and never copied.
     */
    explicit CryptoService(const keys::RootKey& root);

    // Non-copyable, non-movable to ensure strict lifecycle binding
    CryptoService(const CryptoService&) = delete;
    CryptoService& operator=(const CryptoService&) = delete;

    CryptoService(CryptoService&&) = delete;
    CryptoService& operator=(CryptoService&&) = delete;

    ~CryptoService() noexcept;

    /**
     * Encrypt plaintext bound to a specific context.
     */
    CryptoResult encrypt(
        const context::Context& ctx,
        const uint8_t* nonce,
        std::size_t nonce_len,
        const uint8_t* ad,
        std::size_t ad_len,
        const uint8_t* plaintext,
        std::size_t pt_len,
        uint8_t* ciphertext,
        uint8_t* tag,
        std::size_t tag_len
    );

    /**
     * Decrypt ciphertext bound to a specific context.
     * Guaranteed to not write to plaintext if authentication fails.
     */
    CryptoResult decrypt(
        const context::Context& ctx,
        const uint8_t* nonce,
        std::size_t nonce_len,
        const uint8_t* ad,
        std::size_t ad_len,
        const uint8_t* ciphertext,
        std::size_t ct_len,
        const uint8_t* tag,
        std::size_t tag_len,
        uint8_t* plaintext
    );

private:
    const keys::RootKey& root_key_;

    // ChaCha20-Poly1305 requires a 32-byte key
    static constexpr std::size_t kDerivedKeySize = 32;
};

} // namespace api