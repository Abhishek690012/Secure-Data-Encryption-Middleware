#pragma once

#include <cstddef>
#include "util/secure_buffer.hpp"

namespace keys {

/**
 * Owns the system root cryptographic secret.
 * * This class ensures strict ownership of the master secret. It is non-copyable
 * and uses direct containment of a SecureBuffer to guarantee that the 
 * secret is zeroized immediately when the RootKey goes out of scope.
 */
class RootKey {
public:
    /**
     * Constructs a RootKey from raw material.
     * Performs a deep copy into the internal secure buffer.
     * Throws if allocation fails, ensuring an invalid RootKey is never created.
     */
    RootKey(const void* key_data, std::size_t key_len);

    /**
     * Destructor is defaulted as SecureBuffer handles its own zeroization.
     */
    ~RootKey() noexcept = default;

    // Non-copyable: The root key must not be duplicated.
    RootKey(const RootKey&) = delete;
    RootKey& operator=(const RootKey&) = delete;

    // Moveable: Transfers the secret ownership safely.
    RootKey(RootKey&& other) noexcept = default;
    RootKey& operator=(RootKey&& other) noexcept = default;

    /**
     * Provides read-only access to the root key material for KDF usage.
     */
    const void* data() const noexcept;
    std::size_t size() const noexcept;

private:
    // Direct containment: No heap indirection, no manual new/delete.
    util::SecureBuffer key_;
};

} // namespace keys