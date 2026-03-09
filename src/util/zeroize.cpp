#include "util/zeroize.hpp"
#include <cstring>

namespace util {

void zeroize(void* ptr, std::size_t len) noexcept {
    if(ptr == nullptr || len == 0)return;
    
    // Perform the memory overwrite.
    std::memset(ptr, 0, len);

    // Compiler Barrier:
    // 1. ""           : No actual assembly instructions are executed.
    // 2. :            : No output operands.
    // 3. : "r"(ptr)   : Input operand: the pointer is passed in a register.
    // 4. : "memory"   : The clobber list tells the compiler that memory has 
    //                   been modified and must be synchronized.
    // This effectively prevents GCC and Clang from optimizing away the preceding 
    // memset, even if the buffer is never accessed again in the C++ scope.
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

} // namespace util