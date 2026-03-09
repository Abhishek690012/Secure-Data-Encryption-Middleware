#include "util/secure_buffer.hpp"
#include "util/zeroize.hpp"

namespace util {

    //allocater
SecureBuffer::SecureBuffer(std::size_t size) 
    : data_(nullptr), size_(size) {
    if (size_ > 0) {
        data_ = new unsigned char[size_];
        // Initialize with zeros for safety
        util::zeroize(data_, size_);
    }
}

    //destroyer
SecureBuffer::~SecureBuffer() noexcept {
    if (data_) {
        // Securely wipe memory before returning it to the heap
        util::zeroize(data_, size_);
        delete[] data_;//releasing heap memory 
        data_ = nullptr;
    }
}


SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept 
    : data_(other.data_), size_(other.size_) {
    // Transfer ownership and invalidate the source
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // 1. Wipe and release current resource
        if (data_) {
            util::zeroize(data_, size_);
            delete[] data_;
        }

        // 2. Transfer from other
        data_ = other.data_;
        size_ = other.size_;

        // 3. Invalidate other
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void* SecureBuffer::data() noexcept {
    return data_;
}

const void* SecureBuffer::data() const noexcept {
    return data_;
}

std::size_t SecureBuffer::size() const noexcept {
    return size_;
}

} // namespace util