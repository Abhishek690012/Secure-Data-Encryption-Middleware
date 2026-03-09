#include <iostream>
#include <cassert>
#include <cstring>

#include "api/crypto_service.hpp"
#include "keys/root_key.hpp"
#include "context/context.hpp"

// ============================================================================
// Shared Test Constants
// ============================================================================

const uint8_t g_root_key_material[32] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
    0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
};

const uint8_t g_nonce[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
const char* g_ad_str = "unit-associated-data";
const char* g_pt_str = "Test message for encryption";
const char* g_ctx_str = "unit:test";

// ============================================================================
// Test Cases
// ============================================================================

void test_roundtrip() {
    std::cout << "[TEST] Encryption-Decryption roundtrip\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    context::Context ctx(g_ctx_str);

    const uint8_t* ad = reinterpret_cast<const uint8_t*>(g_ad_str);
    std::size_t ad_len = std::strlen(g_ad_str);

    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(g_pt_str);
    std::size_t pt_len = std::strlen(g_pt_str);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};

    // Encrypt
    api::CryptoResult enc_res = service.encrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len,
        plaintext, pt_len,
        ciphertext, tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Decrypt
    api::CryptoResult dec_res = service.decrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len,
        ciphertext, pt_len,
        tag, sizeof(tag),
        decrypted
    );
    assert(dec_res == api::CryptoResult::Success);
    assert(std::memcmp(plaintext, decrypted, pt_len) == 0);

    std::cout << "[PASS] Plaintext recovered successfully\n\n";
}

void test_ciphertext_tampering() {
    std::cout << "[TEST] Ciphertext Tampering Detection\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    context::Context ctx(g_ctx_str);

    const uint8_t* ad = reinterpret_cast<const uint8_t*>(g_ad_str);
    std::size_t ad_len = std::strlen(g_ad_str);

    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(g_pt_str);
    std::size_t pt_len = std::strlen(g_pt_str);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};

    // Encrypt
    api::CryptoResult enc_res = service.encrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, plaintext, pt_len,
        ciphertext, tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF;

    // Decrypt
    api::CryptoResult dec_res = service.decrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, ciphertext, pt_len,
        tag, sizeof(tag), decrypted
    );
    assert(dec_res == api::CryptoResult::AuthenticationFailed);

    std::cout << "[PASS] Ciphertext tampering detected\n\n";
}

void test_tag_tampering() {
    std::cout << "[TEST] Tag Tampering Detection\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    context::Context ctx(g_ctx_str);

    const uint8_t* ad = reinterpret_cast<const uint8_t*>(g_ad_str);
    std::size_t ad_len = std::strlen(g_ad_str);

    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(g_pt_str);
    std::size_t pt_len = std::strlen(g_pt_str);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};

    // Encrypt
    api::CryptoResult enc_res = service.encrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, plaintext, pt_len,
        ciphertext, tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Tamper with tag
    tag[0] ^= 0xFF;

    // Decrypt
    api::CryptoResult dec_res = service.decrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, ciphertext, pt_len,
        tag, sizeof(tag), decrypted
    );
    assert(dec_res == api::CryptoResult::AuthenticationFailed);

    std::cout << "[PASS] Tag tampering detected\n\n";
}

void test_wrong_context() {
    std::cout << "[TEST] Wrong Context Isolation\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    
    context::Context ctx_a("unit:test:A");
    context::Context ctx_b("unit:test:B");

    const uint8_t* ad = reinterpret_cast<const uint8_t*>(g_ad_str);
    std::size_t ad_len = std::strlen(g_ad_str);

    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(g_pt_str);
    std::size_t pt_len = std::strlen(g_pt_str);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};

    // Encrypt with Context A
    api::CryptoResult enc_res = service.encrypt(
        ctx_a, g_nonce, sizeof(g_nonce),
        ad, ad_len, plaintext, pt_len,
        ciphertext, tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Decrypt with Context B
    api::CryptoResult dec_res = service.decrypt(
        ctx_b, g_nonce, sizeof(g_nonce),
        ad, ad_len, ciphertext, pt_len,
        tag, sizeof(tag), decrypted
    );
    assert(dec_res == api::CryptoResult::AuthenticationFailed);

    std::cout << "[PASS] Context separation enforced\n\n";
}

void test_ad_mismatch() {
    std::cout << "[TEST] Associated Data Mismatch\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    context::Context ctx(g_ctx_str);

    const char* ad1_str = "unit-associated-data-1";
    const char* ad2_str = "unit-associated-data-2";

    const uint8_t* ad1 = reinterpret_cast<const uint8_t*>(ad1_str);
    std::size_t ad1_len = std::strlen(ad1_str);

    const uint8_t* ad2 = reinterpret_cast<const uint8_t*>(ad2_str);
    std::size_t ad2_len = std::strlen(ad2_str);

    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(g_pt_str);
    std::size_t pt_len = std::strlen(g_pt_str);

    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};

    // Encrypt with AD 1
    api::CryptoResult enc_res = service.encrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad1, ad1_len, plaintext, pt_len,
        ciphertext, tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Decrypt with AD 2
    api::CryptoResult dec_res = service.decrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad2, ad2_len, ciphertext, pt_len,
        tag, sizeof(tag), decrypted
    );
    assert(dec_res == api::CryptoResult::AuthenticationFailed);

    std::cout << "[PASS] Associated data integrity enforced\n\n";
}

void test_empty_plaintext() {
    std::cout << "[TEST] Empty Plaintext\n";

    keys::RootKey root(g_root_key_material, sizeof(g_root_key_material));
    api::CryptoService service(root);
    context::Context ctx(g_ctx_str);

    const uint8_t* ad = reinterpret_cast<const uint8_t*>(g_ad_str);
    std::size_t ad_len = std::strlen(g_ad_str);

    uint8_t tag[16] = {0};

    // Encrypt with length 0
    api::CryptoResult enc_res = service.encrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, 
        nullptr, 0, // Empty plaintext
        nullptr, // Empty ciphertext
        tag, sizeof(tag)
    );
    assert(enc_res == api::CryptoResult::Success);

    // Decrypt with length 0
    api::CryptoResult dec_res = service.decrypt(
        ctx, g_nonce, sizeof(g_nonce),
        ad, ad_len, 
        nullptr, 0, // Empty ciphertext
        tag, sizeof(tag), 
        nullptr // Empty plaintext
    );
    assert(dec_res == api::CryptoResult::Success);

    std::cout << "[PASS] Zero-length messages handled safely\n\n";
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "Running crypto middleware tests\n\n";

    test_roundtrip();
    test_ciphertext_tampering();
    test_tag_tampering();
    test_wrong_context();
    test_ad_mismatch();
    test_empty_plaintext();

    std::cout << "All tests completed\n";
    return 0;
}