#pragma once

#include "cipherkeeper/crypto/secure_string.hpp"

#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

// The decrypted contents of one vault item. All of it is user content, so every text field is a SecureString and
// the whole item is encrypted as one body (see item_codec.hpp). Item types are move-only; use clone() for a copy.
namespace ck {

// Stored as one byte in the encoded body, so the values must never change.
enum class ItemType : std::uint8_t {
    login = 1,
    secure_note = 2,
    card = 3,
    identity = 4,
};

[[nodiscard]] std::string_view to_string(ItemType type) noexcept;
// Accepts the names to_string returns ("login", "secure_note", "card", "identity").
[[nodiscard]] std::optional<ItemType> parse_item_type(std::string_view name) noexcept;

// A user-defined name/value pair. Hidden fields are masked in the UI, like a password.
struct CustomField {
    SecureString name;
    SecureString value;
    bool hidden = false;

    [[nodiscard]] CustomField clone() const;
    friend bool operator==(const CustomField&, const CustomField&) = default;
};

struct LoginData {
    SecureString username;
    SecureString password;
    std::vector<SecureString> urls;
    SecureString totp_secret; // the shared secret (usually base32) from the site's 2FA setup

    [[nodiscard]] LoginData clone() const;
    friend bool operator==(const LoginData&, const LoginData&) = default;
};

// A secure note has no fields of its own; its text is Item::notes.
struct SecureNoteData {
    // Not static: Item::clone calls clone() on whichever alternative the variant holds.
    [[nodiscard]] SecureNoteData clone() const { return {}; } // NOLINT(readability-convert-member-functions-to-static)
    friend bool operator==(const SecureNoteData&, const SecureNoteData&) = default;
};

// Fields are free text; validating formats (card number checksum, expiry) is the front end's job.
struct CardData {
    SecureString cardholder_name;
    SecureString brand;
    SecureString number;
    SecureString expiry; // e.g. "08/2029"
    SecureString security_code;

    [[nodiscard]] CardData clone() const;
    friend bool operator==(const CardData&, const CardData&) = default;
};

struct IdentityData {
    SecureString first_name;
    SecureString middle_name;
    SecureString last_name;
    SecureString company;
    SecureString email;
    SecureString phone;
    SecureString address_line1;
    SecureString address_line2;
    SecureString city;
    SecureString region; // state, province or county
    SecureString postal_code;
    SecureString country;

    [[nodiscard]] IdentityData clone() const;
    friend bool operator==(const IdentityData&, const IdentityData&) = default;
};

using ItemData = std::variant<LoginData, SecureNoteData, CardData, IdentityData>;

struct Item {
    SecureString title;
    SecureString notes;
    SecureString category; // free text such as "Banking"; empty means uncategorized
    std::vector<SecureString> tags;
    std::vector<CustomField> custom_fields;
    ItemData data;

    // The type follows from which alternative `data` holds.
    [[nodiscard]] ItemType type() const noexcept;
    [[nodiscard]] Item clone() const;
    friend bool operator==(const Item&, const Item&) = default;
};

} // namespace ck
