#pragma once

#include <cipherkeeper/secure_buffer.hpp>

#include <algorithm>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace ck::test {

inline std::vector<std::byte> from_hex(std::string_view hex) {
    const auto nibble = [](char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        throw std::invalid_argument("bad hex digit");
    };
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("odd-length hex string");
    }
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<std::byte>((nibble(hex[i]) << 4) | nibble(hex[i + 1])));
    }
    return out;
}

inline std::span<const std::byte> bytes_of(std::string_view text) {
    return std::as_bytes(std::span(text));
}

// Throwaway test secrets only. Real passwords never appear in tests.
inline SecureBuffer secret(std::string_view text) {
    return SecureBuffer::copy_of(bytes_of(text));
}

inline SecureBuffer secret_from_hex(std::string_view hex) {
    return SecureBuffer::copy_of(from_hex(hex));
}

inline bool same_bytes(std::span<const std::byte> a, std::span<const std::byte> b) {
    return std::ranges::equal(a, b);
}

} // namespace ck::test
