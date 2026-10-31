#pragma once

#include <string_view>

namespace ck {

struct LibraryVersions {
    std::string_view sodium;
    std::string_view sqlite;
};

// Initializes libsodium. Call once at startup before any other core function; calling it again is harmless.
// Returns false if the platform's secure random source is unavailable, in which case the app must exit.
[[nodiscard]] bool initialize() noexcept;

[[nodiscard]] std::string_view version() noexcept;

[[nodiscard]] LibraryVersions library_versions() noexcept;

} // namespace ck
