#include "keys/root_key.hpp"
#include <cstring>

namespace keys {

RootKey::RootKey(const void* key_data, std::size_t key_len)
    : key_(key_len) {
    // Note: SecureBuffer constructor handles allocation and initial zeroing.
    // If the buffer size is 0 or data is null, we essentially have an 
    // empty key, but the object itself remains in a consistent state.
    if (key_data && key_len > 0) {
        std::memcpy(key_.data(), key_data, key_len);
    }
}

const void* RootKey::data() const noexcept {
    return key_.data();
}

std::size_t RootKey::size() const noexcept {
    return key_.size();
}

} // namespace keys