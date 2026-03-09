#pragma once

#include <cstddef>

namespace util {

/**
 * A fixed-size, RAII-compliant memory container for sensitive data.
 * Automatically zeroizes its contents upon destruction or move-assignment.
**/ 
class SecureBuffer {
public:
    // Allocation and Lifetime
    explicit SecureBuffer(std::size_t size);
    ~SecureBuffer() noexcept;

    // Non-copyable: secrets must not be duplicated accidentally
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Moveable: transfer ownership of the secret
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // Accessors
    void* data() noexcept;
    const void* data() const noexcept;
    std::size_t size() const noexcept;

private:
    unsigned char* data_;
    std::size_t size_;
};

} // namespace util