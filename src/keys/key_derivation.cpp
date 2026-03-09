#include "keys/key_derivation.hpp"
#include "keys/root_key.hpp"
#include "context/context.hpp"
#include "util/secure_buffer.hpp"
#include "util/zeroize.hpp"
#include <cstring>
#include <cstdint>

namespace keys {

namespace {

// Standard SHA-256 Constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t right_rotate(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// Self-contained SHA-256 implementation
struct Sha256 {
    static constexpr std::size_t BlockSize = 64;
    static constexpr std::size_t DigestSize = 32;

    uint32_t state[8];
    uint8_t  buffer[BlockSize];
    uint64_t bitlen;
    uint32_t buffer_len;

    Sha256() { reset(); }

    ~Sha256() { util::zeroize(this, sizeof(*this)); }

    void reset() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        bitlen = 0;
        buffer_len = 0;
        std::memset(buffer, 0, BlockSize);
    }

    void transform() {
        uint32_t m[64];
        // Decode buffer into m
        for (int i = 0; i < 16; ++i) {
            m[i] = (static_cast<uint32_t>(buffer[i * 4]) << 24) |
                   (static_cast<uint32_t>(buffer[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(buffer[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(buffer[i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = right_rotate(m[i - 15], 7) ^ right_rotate(m[i - 15], 18) ^ (m[i - 15] >> 3);
            uint32_t s1 = right_rotate(m[i - 2], 17) ^ right_rotate(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + s1 + ch + K[i] + m[i];
            uint32_t s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
        
        util::zeroize(m, sizeof(m));
    }

    void update(const uint8_t* data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            buffer[buffer_len++] = data[i];
            if (buffer_len == BlockSize) {
                transform();
                buffer_len = 0;
                bitlen += 512;
            }
        }
    }

    void final(uint8_t* digest) {
        uint32_t i = buffer_len;
        buffer[i++] = 0x80; // Padding 1 bit
        if (i > 56) {
            std::memset(buffer + i, 0, BlockSize - i);
            transform();
            i = 0;
        }
        std::memset(buffer + i, 0, 56 - i);
        
        uint64_t total_bits = bitlen + buffer_len * 8;
        // Append length (big-endian)
        for(int k=0; k<8; ++k) buffer[56+k] = (total_bits >> (56 - 8*k)) & 0xff;
        
        transform();

        for (i = 0; i < 8; ++i) {
            digest[i * 4]     = (state[i] >> 24) & 0xff;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xff;
            digest[i * 4 + 2] = (state[i] >> 8)  & 0xff;
            digest[i * 4 + 3] = (state[i])       & 0xff;
        }
        reset();
    }
};

// Reduceing code duplication and ensures correct padding/inner/outer hash handling.
class HmacSha256 {
    Sha256 inner_;
    Sha256 outer_;
    uint8_t k_opad_[Sha256::BlockSize];

public:
    HmacSha256(const uint8_t* key, std::size_t key_len) {
        uint8_t k_ipad[Sha256::BlockSize];
        uint8_t tk[Sha256::DigestSize];
        
        // 1. Prepare key
        if (key_len > Sha256::BlockSize) {
            Sha256 kctx;
            kctx.update(key, key_len);
            kctx.final(tk);
            key = tk;
            key_len = Sha256::DigestSize;
        }

        std::memset(k_ipad, 0x36, Sha256::BlockSize);
        std::memset(k_opad_, 0x5c, Sha256::BlockSize);

        for (std::size_t i = 0; i < key_len; ++i) {
            k_ipad[i] ^= key[i];
            k_opad_[i] ^= key[i];
        }
        // XOR remaining bytes of pads with 0 (which is identity for XOR) handled by memset

        // Start Inner Hash
        inner_.update(k_ipad, Sha256::BlockSize);
        
        util::zeroize(k_ipad, sizeof(k_ipad));
        util::zeroize(tk, sizeof(tk));
    }

    ~HmacSha256() {
        util::zeroize(k_opad_, sizeof(k_opad_));
    }

    void update(const uint8_t* data, std::size_t len) {
        inner_.update(data, len);
    }

    void final(uint8_t* out_digest) {
        uint8_t inner_digest[Sha256::DigestSize];
        inner_.final(inner_digest);

        outer_.update(k_opad_, Sha256::BlockSize);
        outer_.update(inner_digest, Sha256::DigestSize);
        outer_.final(out_digest);

        util::zeroize(inner_digest, sizeof(inner_digest));
    }
};

// Fixed, non-secret salt for Root Key derivation (Domain Separation)
const uint8_t kDerivationSalt[] = "SecureMiddleware_HKDF_Salt_v1";

} // namespace anonymous

// Public API Implementation

util::SecureBuffer KeyDerivation::derive(
    const RootKey& root,
    const context::Context& ctx,
    std::size_t out_len) {
    
    util::SecureBuffer derived_key(out_len);
    if (out_len == 0) return derived_key;

    // PRK = HMAC-Hash(salt, IKM)
    uint8_t prk[Sha256::DigestSize]; 
    {
        HmacSha256 hmac(kDerivationSalt, sizeof(kDerivationSalt) - 1); // -1 for null terminator
        hmac.update(static_cast<const uint8_t*>(root.data()), root.size());
        hmac.final(prk);
    }


    // T(0) = empty
    // T(n) = HMAC-Hash(PRK, T(n-1) | info | n)
    
    uint8_t t_block[Sha256::DigestSize];
    std::size_t copied = 0;
    uint8_t counter = 1;

    uint8_t* out_ptr = static_cast<uint8_t*>(derived_key.data());

    while (copied < out_len) {
        HmacSha256 hmac(prk, sizeof(prk));
        
        // T(n-1) (only if n > 1)
        if (counter > 1) {
            hmac.update(t_block, Sha256::DigestSize);
        }
        
        // Context
        if (ctx.data() && ctx.size() > 0) {
            hmac.update(static_cast<const uint8_t*>(ctx.data()), ctx.size());
        }
        
        // Counter
        hmac.update(&counter, 1);
        
        // Calculate T(n)
        hmac.final(t_block);

        std::size_t to_copy = (out_len - copied < Sha256::DigestSize) 
                            ? (out_len - copied) 
                            : Sha256::DigestSize;
        std::memcpy(out_ptr + copied, t_block, to_copy);
        
        copied += to_copy;
        counter++;
    }

    // Cleanup Sensitive Intermediate Data
    util::zeroize(prk, sizeof(prk));
    util::zeroize(t_block, sizeof(t_block));
    
    return derived_key;
}

} // namespace keys