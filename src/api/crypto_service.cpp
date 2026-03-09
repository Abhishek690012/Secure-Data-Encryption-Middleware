#include "api/crypto_service.hpp"
#include "keys/root_key.hpp"
#include "keys/key_derivation.hpp"
#include "context/context.hpp"
#include "crypto/aead.hpp"
#include "util/secure_buffer.hpp"

namespace api {

namespace {
    // Utility function to translate internal AEAD results to public API results
    CryptoResult translate_aead_result(crypto::AeadResult result) noexcept {
        switch (result) {
            case crypto::AeadResult::Success:
                return CryptoResult::Success;
            case crypto::AeadResult::AuthenticationFailed:
                return CryptoResult::AuthenticationFailed;
            case crypto::AeadResult::InvalidInput:
            default:
                return CryptoResult::InvalidInput;
        }
    }
} // namespace anonymous

CryptoService::CryptoService(const keys::RootKey& root)
    : root_key_(root) {
}

CryptoService::~CryptoService() noexcept {
    // Nothing to zeroize here; the root key is owned externally,
    // and derived keys are handled by RAII within method scopes.
}

CryptoResult CryptoService::encrypt(
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
) {
    // Basic input validation
    if ((pt_len > 0 && (!plaintext || !ciphertext)) ||
        (nonce_len > 0 && !nonce) ||
        (tag_len > 0 && !tag) ||
        (ad_len > 0 && !ad)) {
        return CryptoResult::InvalidInput;
    }

    // 1. Derive the context-specific key.
    // The resulting derived_key (util::SecureBuffer) owns the memory 
    // and is guaranteed to securely wipe it when it goes out of scope.
    util::SecureBuffer derived_key = keys::KeyDerivation::derive(root_key_, ctx, kDerivedKeySize);

    // 2. Perform Authenticated Encryption.
    crypto::AeadResult res = crypto::Aead::encrypt(
        derived_key,
        nonce, nonce_len,
        ad, ad_len,
        plaintext, pt_len,
        ciphertext,
        tag, tag_len
    );

    // 3. Translate and return result.
    return translate_aead_result(res);
}

CryptoResult CryptoService::decrypt(
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
) {
    // Basic input validation
    if ((ct_len > 0 && (!ciphertext || !plaintext)) ||
        (nonce_len > 0 && !nonce) ||
        (tag_len > 0 && !tag) ||
        (ad_len > 0 && !ad)) {
        return CryptoResult::InvalidInput;
    }

    // 1. Derive the context-specific key matching the encryption step.
    util::SecureBuffer derived_key = keys::KeyDerivation::derive(root_key_, ctx, kDerivedKeySize);

    // 2. Perform Authenticated Decryption.
    // The Aead layer handles Verify-Before-Decrypt and ensures plaintext 
    // is not written if the authentication tag is invalid.
    crypto::AeadResult res = crypto::Aead::decrypt(
        derived_key,
        nonce, nonce_len,
        ad, ad_len,
        ciphertext, ct_len,
        tag, tag_len,
        plaintext
    );

    // 3. Translate and return result.
    return translate_aead_result(res);
}

} // namespace api