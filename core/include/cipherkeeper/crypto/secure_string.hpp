#pragma once

#include "cipherkeeper/crypto/secure_buffer.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace ck {

// UTF-8 text held in a SecureBuffer: locked memory, wiped on destruction, move-only. Use it for every piece of
// user-entered vault content. The text is copied in on construction and is read-only afterwards; to change it,
// assign a new SecureString.
//
// Each non-empty SecureString is its own sodium_malloc allocation (several pages with guard pages), so hold them
// for the items being shown or edited, not for a whole vault at once.
class SecureString {
  public:
    SecureString() noexcept = default;
    explicit SecureString(std::string_view text) : buffer_(SecureBuffer::copy_of(std::as_bytes(std::span(text)))) {}

    [[nodiscard]] std::string_view view() const noexcept {
        return {reinterpret_cast<const char*>(buffer_.data()), buffer_.size()};
    }
    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return buffer_.bytes(); }
    [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
    [[nodiscard]] bool empty() const noexcept { return buffer_.empty(); }

    // An explicit copy, since copies of secrets should be deliberate.
    [[nodiscard]] SecureString clone() const { return SecureString(view()); }

    // Constant-time for equal lengths (sodium_memcmp).
    friend bool operator==(const SecureString& a, const SecureString& b) noexcept;

  private:
    SecureBuffer buffer_;
};

} // namespace ck
