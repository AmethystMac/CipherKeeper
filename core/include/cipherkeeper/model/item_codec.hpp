#pragma once

#include "cipherkeeper/crypto/secure_buffer.hpp"
#include "cipherkeeper/model/item.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

// Converts an Item to and from the plaintext body that Vault encrypts. The format is versioned and length-prefixed;
// it is described at the top of item_codec.cpp.
namespace ck {

// Thrown by decode_item. Messages never contain item contents.
class ItemFormatError : public std::runtime_error {
  public:
    enum class Kind : std::uint8_t {
        unsupported_version, // written by a newer CipherKeeper
        malformed,           // anything else: bad magic, truncation, unknown or duplicate fields, trailing bytes
    };

    ItemFormatError(Kind kind, const std::string& message) : std::runtime_error(message), kind_(kind) {}

    [[nodiscard]] Kind kind() const noexcept { return kind_; }

  private:
    Kind kind_;
};

// The encoded body is built directly in secure memory. Empty single-value fields are left out, so an Item always
// encodes to the same bytes.
[[nodiscard]] SecureBuffer encode_item(const Item& item);

// Throws ItemFormatError. Never reads outside `body`, whatever it contains.
[[nodiscard]] Item decode_item(std::span<const std::byte> body);

} // namespace ck
