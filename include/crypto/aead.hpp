#pragma once

#include <cstddef>
#include <cstdint>

namespace util {
class SecureBuffer;
}

namespace crypto {

/**
 * Result codes for AEAD operations.
 */
enum class AeadResult {
    Success,
    AuthenticationFailed,
    InvalidInput
};

/**
 * Authenticated Encryption with Associated Data (AEAD).
 * Implements ChaCha20-Poly1305 (RFC 8439).
 * * Provides confidentiality, integrity, and authenticity.
 * Ensures that if the ciphertext or associated data is tampered with,
 * decryption will fail safely without revealing plaintext.
 */
class Aead {
public:
    // Constants for ChaCha20-Poly1305
    static constexpr std::size_t KeySize = 32;
    static constexpr std::size_t NonceSize = 12;
    static constexpr std::size_t TagSize = 16;

    /**
     * Encrypt plaintext with associated data.
     *
     * @param key        Derived encryption key (Must be 32 bytes)
     * @param nonce      Unique nonce (Must be 12 bytes)
     * @param nonce_len  Length of nonce
     * @param ad         Associated data (may be null)
     * @param ad_len     Length of associated data
     * @param plaintext  Input plaintext
     * @param pt_len     Length of plaintext
     * @param ciphertext Output buffer (Must be at least pt_len)
     * @param tag        Output authentication tag (Must be 16 bytes)
     * @param tag_len    Length of tag buffer
     */
    static AeadResult encrypt(
        const util::SecureBuffer& key,
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
     * Decrypt ciphertext with associated data.
     *
     * @param key        Derived encryption key (Must be 32 bytes)
     * @param nonce      Unique nonce (Must be 12 bytes)
     * @param nonce_len  Length of nonce
     * @param ad         Associated data (Must match encryption AD)
     * @param ad_len     Length of associated data
     * @param ciphertext Input ciphertext
     * @param ct_len     Length of ciphertext
     * @param tag        Input authentication tag
     * @param tag_len    Length of tag buffer
     * @param plaintext  Output buffer (Must be at least ct_len). 
     * Only written to if authentication succeeds.
     *
     * @return AuthenticationFailed if tag verification fails, Success otherwise.
     */
    static AeadResult decrypt(
        const util::SecureBuffer& key,
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
    Aead() = delete;
};

} // namespace crypto