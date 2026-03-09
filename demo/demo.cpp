#include "api/crypto_service.hpp"
#include "keys/root_key.hpp"
#include "context/context.hpp"

#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdint>

// Utility function to cleanly print hexadecimal data
void print_hex(const char* label, const uint8_t* data, std::size_t len) {
    std::cout << label << " (hex): ";
    for (std::size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::cout << "===============================\n";
    std::cout << "Crypto Middleware Demo\n";
    std::cout << "===============================\n\n";


    //  Root Key & Service Initialization
    std::cout << "[STEP] Initializing Root Key\n";
    
    uint8_t root_key_material[32] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    };

    keys::RootKey root(root_key_material, sizeof(root_key_material));
    api::CryptoService service(root);
    
    std::cout << "[OK] Root key initialized\n\n";


    //Context Creation

    std::cout << "[STEP] Creating encryption context\n";
    const char* ctx_string = "demo:file_encryption";
    context::Context ctx(ctx_string);
    std::cout << "[INFO] Context = " << ctx_string << "\n\n";

    // Prepare Inputs
  
    std::cout << "[STEP] Preparing plaintext\n";
    
    const char* pt_str = "The quick brown fox jumps over the lazy dog";
    const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(pt_str);
    std::size_t pt_len = std::strlen(pt_str);
    
    std::cout << "[INFO] Plaintext length: " << pt_len << " bytes\n";
    std::cout << "[INFO] Plaintext message:\n\"" << pt_str << "\"\n";

    uint8_t nonce[12] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
    std::cout << "[INFO] Nonce size = 12 bytes\n";

    const char* ad_str = "demo-associated-data";
    const uint8_t* ad = reinterpret_cast<const uint8_t*>(ad_str);
    std::size_t ad_len = std::strlen(ad_str);
    std::cout << "[INFO] Associated data attached\n\n";

    // Stack-allocated buffer
    uint8_t ciphertext[256] = {0};
    uint8_t decrypted[256] = {0};
    uint8_t tag[16] = {0};


    // Encryption
    std::cout << "[STEP] Performing encryption\n";

    api::CryptoResult enc_result = service.encrypt(
        ctx,
        nonce, sizeof(nonce),
        ad, ad_len,
        plaintext, pt_len,
        ciphertext,
        tag, sizeof(tag)
    );

    if (enc_result == api::CryptoResult::Success) {
        std::cout << "[OK] Encryption successful\n\n";
        print_hex("Ciphertext", ciphertext, pt_len);
        print_hex("Tag", tag, sizeof(tag));
        std::cout << "\n";
    } else {
        std::cout << "[ERROR] Encryption failed\n\n";
        return 1;
    }

    // 5. Decryption

    std::cout << "[STEP] Attempt decryption\n";

    api::CryptoResult dec_result = service.decrypt(
        ctx,
        nonce, sizeof(nonce),
        ad, ad_len,
        ciphertext, pt_len,
        tag, sizeof(tag),
        decrypted
    );

    if (dec_result == api::CryptoResult::Success) {
        std::cout << "[OK] Decryption successful\n\n";
        // Ensure null-termination before printing
        decrypted[pt_len] = '\0';
        std::cout << "Recovered plaintext:\n" << reinterpret_cast<char*>(decrypted) << "\n\n";
    } else {
        std::cout << "[ERROR] Decryption failed\n\n";
        return 1;
    }


    // Tampering Test
    std::cout << "[STEP] Tampering test\n";
    
    // Flip bits in the first byte of the ciphertext
    ciphertext[0] ^= 0xFF;
    std::cout << "[INFO] Ciphertext modified\n\n";

    // Clear decrypted buffer to prove we are not seeing old data
    std::memset(decrypted, 0, sizeof(decrypted));

    api::CryptoResult tamper_result = service.decrypt(
        ctx,
        nonce, sizeof(nonce),
        ad, ad_len,
        ciphertext, pt_len,
        tag, sizeof(tag),
        decrypted
    );

    if (tamper_result == api::CryptoResult::AuthenticationFailed) {
        std::cout << "[OK] Authentication failure detected\n";
    } else if (tamper_result == api::CryptoResult::Success) {
        std::cout << "[ERROR] Tampering was NOT detected\n";
        return 1;
    } else {
        std::cout << "[ERROR] Unexpected failure mode during tampering test\n";
        return 1;
    }

    return 0;
}