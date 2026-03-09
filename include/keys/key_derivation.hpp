#pragma once

#include <cstddef>

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

namespace keys {

/**
 * Provides a canonical mechanism for deriving context-bound keys.
 * * This module implements a domain-separation pattern that ensures different
 * contexts yield cryptographically independent keys from the same root secret.
 */
class KeyDerivation {
public:
    /**
     * Derive a fixed-size key from the root secret, bound to a specific context.
     *
     * @param root    The system root key (accessed read-only).
     * @param ctx     The cryptographic context defining the logical domain.
     * @param out_len The requested length of the derived key in bytes.
     *
     * @return A util::SecureBuffer containing the derived key material.
     * The buffer is automatically zeroized upon destruction.
     */
    static util::SecureBuffer derive(
        const RootKey& root,
        const context::Context& ctx,
        std::size_t out_len
    );

private:
    // This is a static utility class; instantiation is disallowed.
    KeyDerivation() = delete;
};

} // namespace keys