#pragma once

#include <cstddef>

namespace context {

/**
 * Represents an immutable cryptographic context.
 * Used for domain separation in key derivation (KDF) and associated data (AD).
 * Contexts are considered public metadata, not secrets, and thus are not zeroized.
 */
class Context {
public:
    // Construction from raw memory - performs deep copy
    Context(const void* data, std::size_t len);

    // Construction from C-string (excluding null terminator)
    explicit Context(const char* str);

    // Contexts are immutable and safe to copy/assign
    ~Context() noexcept;
    Context(const Context& other);
    Context& operator=(const Context& other);

    // Move support
    Context(Context&& other) noexcept;
    Context& operator=(Context&& other) noexcept;

    // Accessors - Pointers are strictly const to ensure immutability
    const void* data() const noexcept;
    std::size_t size() const noexcept;

private:
    unsigned char* data_;
    std::size_t size_;

    void allocate_and_copy(const void* src, std::size_t len);
    void clear() noexcept;
};

} // namespace context