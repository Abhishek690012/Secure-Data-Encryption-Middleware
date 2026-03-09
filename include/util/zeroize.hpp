#pragma once

#include <cstddef>

namespace util {

/**
 * Securely overwrite a memory region with zeros.
 * Guaranteed not to be optimized away by the compiler.
 * * This is used for erasing cryptographic keys and sensitive intermediate buffers.
 * The operation is deterministic and immediate.
 */
void zeroize(void* ptr, std::size_t len) noexcept;

} // namespace util