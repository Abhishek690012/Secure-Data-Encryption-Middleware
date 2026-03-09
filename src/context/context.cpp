#include "context/context.hpp"
#include <cstring>
#include <algorithm>

namespace context {

Context::Context(const void* data, std::size_t len) 
    : data_(nullptr), size_(0) {
    if (data && len > 0) {
        allocate_and_copy(data, len);
    }
}

Context::Context(const char* str) 
    : data_(nullptr), size_(0) {
    if (str) {
        std::size_t len = std::strlen(str);
        if (len > 0) {
            allocate_and_copy(str, len);
        }
    }
}

Context::~Context() noexcept { 
    clear();
}

Context::Context(const Context& other) 
    : data_(nullptr), size_(0) {
    if (other.data_ && other.size_ > 0) {
        allocate_and_copy(other.data_, other.size_);
    }
}

Context& Context::operator=(const Context& other) {
    if (this != &other) {
        clear();
        if (other.data_ && other.size_ > 0) {
            allocate_and_copy(other.data_, other.size_);
        }
    }
    return *this;
}

Context::Context(Context&& other) noexcept 
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

Context& Context::operator=(Context&& other) noexcept {
    if (this != &other) {
        clear();
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

const void* Context::data() const noexcept {
    return data_;
}

std::size_t Context::size() const noexcept {
    return size_;
}

void Context::allocate_and_copy(const void* src, std::size_t len) {
    data_ = new unsigned char[len];
    size_ = len;
    std::memcpy(data_, src, len);
}

void Context::clear() noexcept {
    delete[] data_;
    data_ = nullptr;
    size_ = 0;
}

} // namespace context