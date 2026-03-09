#include "crypto/aead.hpp"
#include "util/secure_buffer.hpp"
#include "util/zeroize.hpp"
#include <cstring>
#include <algorithm>
#include <limits>

namespace crypto {

namespace {

// ============================================================================
// Internal Primitives: ChaCha20 & Poly1305 (RFC 8439)
// ============================================================================

// ChaCha20 constants
constexpr uint64_t kChaChaBlockSize = 64;
// Limit to 2^32 - 1 blocks to prevent counter overflow
constexpr uint64_t kMaxMessageLen = (static_cast<uint64_t>(1) << 32) * kChaChaBlockSize - kChaChaBlockSize;

// --- Utilities ---

inline uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

inline void store64_le(uint8_t* p, uint64_t v) {
    store32_le(p, (uint32_t)v);
    store32_le(p + 4, (uint32_t)(v >> 32));
}

inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Constant-time comparison for tags
bool constant_time_equals(const uint8_t* a, const uint8_t* b, std::size_t len) {
    volatile uint8_t result = 0;
    for (std::size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

// --- ChaCha20 ---

struct ChaCha20State {
    uint32_t s[16];

    ChaCha20State() { std::memset(s, 0, sizeof(s)); }
    ~ChaCha20State() { util::zeroize(s, sizeof(s)); }

    void init(const uint8_t* key, const uint8_t* nonce, uint32_t counter) {
        // "expand 32-byte k"
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
        
        s[4] = load32_le(key + 0);  s[5] = load32_le(key + 4);
        s[6] = load32_le(key + 8);  s[7] = load32_le(key + 12);
        s[8] = load32_le(key + 16); s[9] = load32_le(key + 20);
        s[10]= load32_le(key + 24); s[11]= load32_le(key + 28);
        
        s[12] = counter;
        s[13] = load32_le(nonce + 0);
        s[14] = load32_le(nonce + 4);
        s[15] = load32_le(nonce + 8);
    }

    void quarter_round(int a, int b, int c, int d) {
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
        s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
        s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
    }

    void block(uint8_t output[64]) {
        uint32_t working_state[16];
        std::memcpy(working_state, s, sizeof(working_state));

        for (int i = 0; i < 10; ++i) {
            // Column rounds
            quarter_round(0, 4, 8, 12);
            quarter_round(1, 5, 9, 13);
            quarter_round(2, 6, 10, 14);
            quarter_round(3, 7, 11, 15);
            // Diagonal rounds
            quarter_round(0, 5, 10, 15);
            quarter_round(1, 6, 11, 12);
            quarter_round(2, 7, 8, 13);
            quarter_round(3, 4, 9, 14);
        }

        for (int i = 0; i < 16; ++i) {
            store32_le(output + 4 * i, working_state[i] + s[i]);
        }
        
        util::zeroize(working_state, sizeof(working_state));
    }

    void process_stream(const uint8_t* input, uint8_t* output, std::size_t len) {
        uint8_t keystream[64];
        std::size_t offset = 0;

        while (offset < len) {
            block(keystream);
            s[12]++; // Increment counter

            std::size_t chunk = std::min<std::size_t>(len - offset, 64);
            for (std::size_t i = 0; i < chunk; ++i) {
                output[offset + i] = (input ? input[offset + i] : 0) ^ keystream[i];
            }
            offset += chunk;
        }
        util::zeroize(keystream, sizeof(keystream));
    }
};

// --- Poly1305 ---

/**
 * Standard 32-bit implementation of Poly1305.
 * Uses 5 26-bit limbs for accumulator and key.
 * * Mathematical Definition:
 * accumulator = (accumulator + block + 2^128) * r % p
 * * Note: RFC 8439 requires that all inputs to Poly1305 be padded to 16 bytes
 * with zeros. The implicit high bit (2^128) is handled by the process_block 
 * function internally.
 */
class Poly1305 {
    uint32_t r[5];       // Key limbs (clamped)
    uint32_t h[5];       // Accumulator limbs
    uint32_t pad[4];     // Final addition key
    uint8_t  buffer[16]; // Input buffer
    std::size_t buffer_len;

public:
    Poly1305(const uint8_t key[32]) {
        // Initialize accumulator to 0
        std::memset(h, 0, sizeof(h));
        buffer_len = 0;

        // Load R (key[0..15]) and clamp
        uint32_t t0 = load32_le(key + 0);
        uint32_t t1 = load32_le(key + 4);
        uint32_t t2 = load32_le(key + 8);
        uint32_t t3 = load32_le(key + 12);

        r[0] = t0 & 0x03ffffff;
        r[1] = (t0 >> 26) | ((t1 << 6) & 0x03ffffc0);
        r[2] = (t1 >> 20) | ((t2 << 12) & 0x03ffc000);
        r[3] = (t2 >> 14) | ((t3 << 18) & 0x03f00000);
        r[4] = (t3 >> 8)  & 0x000fffff;

        // Clamp R
        r[1] &= 0x03ffff03;
        r[2] &= 0x03ffc0ff;
        r[3] &= 0x03f03fff;
        r[4] &= 0x000fffff;

        // Load S/Pad (key[16..31])
        pad[0] = load32_le(key + 16);
        pad[1] = load32_le(key + 20);
        pad[2] = load32_le(key + 24);
        pad[3] = load32_le(key + 28);
    }

    ~Poly1305() {
        util::zeroize(r, sizeof(r));
        util::zeroize(h, sizeof(h));
        util::zeroize(pad, sizeof(pad));
        util::zeroize(buffer, sizeof(buffer));
    }

    void update(const uint8_t* data, std::size_t len) {
        std::size_t offset = 0;
        while (offset < len) {
            std::size_t chunk = std::min<std::size_t>(16 - buffer_len, len - offset);
            std::memcpy(buffer + buffer_len, data + offset, chunk);
            buffer_len += chunk;
            offset += chunk;

            if (buffer_len == 16) {
                process_block(buffer);
                buffer_len = 0;
            }
        }
    }

    void finish(uint8_t mac[16]) {
        if (buffer_len > 0) {
            // RFC 8439: Last partial block is zero-padded to 16 bytes.
            std::memset(buffer + buffer_len, 0, 16 - buffer_len);
            
            // We do NOT set buffer[buffer_len] = 1.
            // The process_block function intrinsically adds 2^128 (the high bit)
            // to every 16-byte block processed, which is the correct mathematical
            // definition for Poly1305.
            process_block(buffer);
        }

        // Finalize: h %= 2^128
        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

        // Carry propagation
        uint32_t c;
        c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;
        c = h1 >> 26; h1 = h1 & 0x3ffffff; h2 += c;
        c = h2 >> 26; h2 = h2 & 0x3ffffff; h3 += c;
        c = h3 >> 26; h3 = h3 & 0x3ffffff; h4 += c;
        c = h4 >> 26; h4 = h4 & 0x3ffffff; h0 += c * 5;

        c = h0 >> 26; h0 = h0 & 0x3ffffff; h1 += c;

        // Compute h + 5
        uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
        uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
        uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
        uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
        uint32_t g4 = h4 + c - (1 << 26);

        uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // Convert back to 32-bit words
        uint64_t f0 = ((uint64_t)h0      ) | ((uint64_t)h1 << 26);
        uint64_t f1 = ((uint64_t)h1 >>  6) | ((uint64_t)h2 << 20);
        uint64_t f2 = ((uint64_t)h2 >> 12) | ((uint64_t)h3 << 14);
        uint64_t f3 = ((uint64_t)h3 >> 18) | ((uint64_t)h4 <<  8);

        // Add pad
        f0 += pad[0];
        f1 += pad[1];
        f2 += pad[2];
        f3 += pad[3];

        store32_le(mac + 0, (uint32_t)f0);
        store32_le(mac + 4, (uint32_t)f1);
        store32_le(mac + 8, (uint32_t)f2);
        store32_le(mac + 12,(uint32_t)f3);
    }

private:
    void process_block(const uint8_t* m) {
        // Load message into limbs
        uint32_t t0 = load32_le(m + 0);
        uint32_t t1 = load32_le(m + 4);
        uint32_t t2 = load32_le(m + 8);
        uint32_t t3 = load32_le(m + 12);

        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];

        // h += m
        h0 += t0 & 0x03ffffff;
        h1 += (t0 >> 26) | ((t1 << 6) & 0x03ffffc0);
        h2 += (t1 >> 20) | ((t2 << 12) & 0x03ffc000);
        h3 += (t2 >> 14) | ((t3 << 18) & 0x03f00000);
        h4 += (t3 >> 8);

        // Add 2^128 (bit 24 of h4, since h4 stores bits 104..129)
        // 104 + 24 = 128
        h4 += (1 << 24);

        // r * h
        uint64_t d0, d1, d2, d3, d4;
        uint32_t s1 = r[1] * 5;
        uint32_t s2 = r[2] * 5;
        uint32_t s3 = r[3] * 5;
        uint32_t s4 = r[4] * 5;

        d0 = (uint64_t)h0 * r[0] + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r[1] + (uint64_t)h1 * r[0] + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r[2] + (uint64_t)h1 * r[1] + (uint64_t)h2 * r[0] + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r[3] + (uint64_t)h1 * r[2] + (uint64_t)h2 * r[1] + (uint64_t)h3 * r[0] + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r[4] + (uint64_t)h1 * r[3] + (uint64_t)h2 * r[2] + (uint64_t)h3 * r[1] + (uint64_t)h4 * r[0];

        // Reduce
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h[0] = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h[1] = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h[2] = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h[3] = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h[4] = (uint32_t)d4 & 0x3ffffff; h[0] += c * 5;
        
        c = (h[0] >> 26); h[0] &= 0x3ffffff; h[1] += c;
    }
};

} // namespace anonymous

// ============================================================================
// Public API Implementation
// ============================================================================

AeadResult Aead::encrypt(
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
) {
    // Validate inputs and enforcement of limits
    if (key.size() != KeySize || nonce_len != NonceSize || tag_len != TagSize) {
        return AeadResult::InvalidInput;
    }

    if (pt_len > kMaxMessageLen || ad_len > kMaxMessageLen) {
        return AeadResult::InvalidInput;
    }

    // 1. Generate Poly1305 Key (OTK)
    ChaCha20State chacha;
    chacha.init(static_cast<const uint8_t*>(key.data()), nonce, 0);
    
    uint8_t block0[64];
    chacha.block(block0);
    
    // 2. Initialize Poly1305 with first 32 bytes of block0
    Poly1305 poly(block0);
    util::zeroize(block0, sizeof(block0));

    // 3. Encrypt Plaintext -> Ciphertext
    chacha.init(static_cast<const uint8_t*>(key.data()), nonce, 1);
    chacha.process_stream(plaintext, ciphertext, pt_len);

    // 4. Calculate Tag (RFC 8439)
    // Mac(AD | pad | CT | pad | len(AD) | len(CT))
    
    // AD
    if (ad && ad_len > 0) {
        poly.update(ad, ad_len);
        if (ad_len % 16 != 0) {
            uint8_t zeros[16] = {0};
            poly.update(zeros, 16 - (ad_len % 16));
        }
    }

    // Ciphertext
    if (ciphertext && pt_len > 0) {
        poly.update(ciphertext, pt_len);
        if (pt_len % 16 != 0) {
            uint8_t zeros[16] = {0};
            poly.update(zeros, 16 - (pt_len % 16));
        }
    }

    // Lengths
    uint8_t len_buf[16];
    store64_le(len_buf, (uint64_t)ad_len);
    store64_le(len_buf + 8, (uint64_t)pt_len);
    poly.update(len_buf, 16);

    poly.finish(tag);

    return AeadResult::Success;
}

AeadResult Aead::decrypt(
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
) {
    if (key.size() != KeySize || nonce_len != NonceSize || tag_len != TagSize) {
        return AeadResult::InvalidInput;
    }

    if (ct_len > kMaxMessageLen || ad_len > kMaxMessageLen) {
        return AeadResult::InvalidInput;
    }

    // 1. Re-calculate Poly1305 Key (OTK)
    ChaCha20State chacha;
    chacha.init(static_cast<const uint8_t*>(key.data()), nonce, 0);
    
    uint8_t block0[64];
    chacha.block(block0);
    
    // 2. Calculate expected Tag
    Poly1305 poly(block0);
    util::zeroize(block0, sizeof(block0));

    // AD
    if (ad && ad_len > 0) {
        poly.update(ad, ad_len);
        if (ad_len % 16 != 0) {
            uint8_t zeros[16] = {0};
            poly.update(zeros, 16 - (ad_len % 16));
        }
    }

    // Ciphertext
    if (ciphertext && ct_len > 0) {
        poly.update(ciphertext, ct_len);
        if (ct_len % 16 != 0) {
            uint8_t zeros[16] = {0};
            poly.update(zeros, 16 - (ct_len % 16));
        }
    }

    // Lengths
    uint8_t len_buf[16];
    store64_le(len_buf, (uint64_t)ad_len);
    store64_le(len_buf + 8, (uint64_t)ct_len);
    poly.update(len_buf, 16);

    uint8_t expected_tag[16];
    poly.finish(expected_tag);

    // 3. Verify Tag (Constant Time)
    if (!constant_time_equals(tag, expected_tag, TagSize)) {
        util::zeroize(expected_tag, sizeof(expected_tag));
        return AeadResult::AuthenticationFailed;
    }
    util::zeroize(expected_tag, sizeof(expected_tag));

    // 4. Decrypt (Only after verification)
    chacha.init(static_cast<const uint8_t*>(key.data()), nonce, 1);
    chacha.process_stream(ciphertext, plaintext, ct_len);

    return AeadResult::Success;
}

} // namespace crypto