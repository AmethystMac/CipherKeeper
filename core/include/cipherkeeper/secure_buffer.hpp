#pragma once

#include <cstddef>
#include <span>

namespace ck {

// Owns a fixed-size block of secret bytes (keys, passwords, decrypted item bodies).
//
// The memory comes from sodium_malloc: it is locked so it is never swapped to disk, sits between guard pages,
// and is wiped by sodium_free on destruction. A new buffer is zero-filled. Buffers are move-only, so a secret is
// never copied by accident; use copy_of() when a copy is really needed.
class SecureBuffer {
  public:
    SecureBuffer() noexcept = default;

    // Throws std::bad_alloc if the allocation fails, or std::runtime_error if libsodium can't be initialized.
    explicit SecureBuffer(std::size_t size);

    [[nodiscard]] static SecureBuffer copy_of(std::span<const std::byte> bytes);

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;
    ~SecureBuffer();

    [[nodiscard]] std::byte* data() noexcept { return data_; }
    [[nodiscard]] const std::byte* data() const noexcept { return data_; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

    [[nodiscard]] std::span<std::byte> bytes() noexcept { return {data_, size_}; }
    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return {data_, size_}; }

    // Wipes and frees the contents, leaving an empty buffer.
    void reset() noexcept;

  private:
    std::byte* data_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace ck
