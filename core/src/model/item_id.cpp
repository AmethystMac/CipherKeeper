#include "cipherkeeper/model/item_id.hpp"

#include "cipherkeeper/crypto/crypto.hpp"

#include <algorithm>

namespace ck {

namespace {

// Byte offsets after which the canonical form has a dash.
constexpr std::array<std::size_t, 4> dash_after{3, 5, 7, 9};
constexpr std::size_t text_size = (ItemId::size * 2) + dash_after.size();

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

} // namespace

ItemId ItemId::generate() {
    ItemId id;
    crypto::random_bytes(id.bytes_);
    // RFC 9562 §5.4: version 4 in the high nibble of byte 6, variant 0b10 in the top bits of byte 8.
    id.bytes_[6] = (id.bytes_[6] & std::byte{0x0f}) | std::byte{0x40};
    id.bytes_[8] = (id.bytes_[8] & std::byte{0x3f}) | std::byte{0x80};
    return id;
}

ItemId ItemId::from_bytes(std::span<const std::byte, size> bytes) noexcept {
    ItemId id;
    std::ranges::copy(bytes, id.bytes_.begin());
    return id;
}

std::optional<ItemId> ItemId::parse(std::string_view text) {
    if (text.size() != text_size) {
        return std::nullopt;
    }
    ItemId id;
    std::size_t pos = 0;
    for (std::size_t i = 0; i < size; ++i) {
        const int high = hex_value(text[pos]);
        const int low = hex_value(text[pos + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        id.bytes_.at(i) = static_cast<std::byte>((high << 4) | low);
        pos += 2;
        if (std::ranges::find(dash_after, i) != dash_after.end()) {
            if (text[pos] != '-') {
                return std::nullopt;
            }
            ++pos;
        }
    }
    return id;
}

std::string ItemId::to_string() const {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string text;
    text.reserve(text_size);
    for (std::size_t i = 0; const std::byte byte : bytes_) {
        const auto value = std::to_integer<unsigned>(byte);
        text.push_back(digits[value >> 4U]);
        text.push_back(digits[value & 0x0fU]);
        if (std::ranges::find(dash_after, i) != dash_after.end()) {
            text.push_back('-');
        }
        ++i;
    }
    return text;
}

} // namespace ck
