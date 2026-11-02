#pragma once

#include <array>
#include <compare>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace ck {

// A random (version 4) UUID identifying one vault item. Stored as 16 raw bytes; shown and parsed in the canonical
// lowercase form "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".
class ItemId {
  public:
    static constexpr std::size_t size = 16;

    [[nodiscard]] static ItemId generate();
    [[nodiscard]] static ItemId from_bytes(std::span<const std::byte, size> bytes) noexcept;
    // Accepts the canonical 36-character form, in either case. Returns std::nullopt for anything else.
    [[nodiscard]] static std::optional<ItemId> parse(std::string_view text);

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::span<const std::byte, size> bytes() const noexcept { return bytes_; }

    friend auto operator<=>(const ItemId&, const ItemId&) = default;

  private:
    std::array<std::byte, size> bytes_{};
};

} // namespace ck
