#include "cipherkeeper/crypto/secure_buffer.hpp"

#include <sodium.h>

#include <algorithm>
#include <new>
#include <stdexcept>
#include <utility>

namespace ck {

SecureBuffer::SecureBuffer(std::size_t size) {
    if (size == 0) {
        return;
    }
    // sodium_malloc needs the page size that sodium_init records. sodium_init is idempotent and thread-safe, so
    // calling it here protects callers that forgot ck::initialize().
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium could not be initialized");
    }
    data_ = static_cast<std::byte*>(sodium_malloc(size));
    if (data_ == nullptr) {
        throw std::bad_alloc();
    }
    size_ = size;
    // sodium_malloc fills new memory with 0xdb. Zeroing it makes a fresh buffer predictable.
    sodium_memzero(data_, size_);
}

SecureBuffer SecureBuffer::copy_of(std::span<const std::byte> bytes) {
    SecureBuffer copy(bytes.size());
    std::ranges::copy(bytes, copy.bytes().begin());
    return copy;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    reset();
}

void SecureBuffer::reset() noexcept {
    // sodium_free wipes the memory before releasing it, and accepts nullptr.
    sodium_free(data_);
    data_ = nullptr;
    size_ = 0;
}

} // namespace ck
