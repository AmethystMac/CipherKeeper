#pragma once

#include <cipherkeeper/crypto/secure_string.hpp>
#include <cipherkeeper/model/item.hpp>

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

// One table drives add, edit and get, so prompts, display and --field names can't drift apart.
namespace ck::cli {

enum class FieldKind : std::uint8_t {
    text,       // one value
    words,      // a list entered space-separated (URLs)
    comma_list, // a list entered comma-separated (tags)
};

// A view of one field of an Item. Exactly one of `text` and `list` is set, pointing into the Item.
struct Field {
    std::string_view label; // prompt and display label
    std::string_view name;  // the `get --field` name
    bool secret = false;    // read without echo, masked by get
    FieldKind kind = FieldKind::text;
    SecureString* text = nullptr;
    std::vector<SecureString>* list = nullptr;

    [[nodiscard]] bool empty() const noexcept { return text != nullptr ? text->empty() : list->empty(); }
};

// The item's fields in prompt order: Title, the type's own fields, Category, Tags, Notes. Custom fields aren't
// included. The views stay valid while `item` isn't moved or reassigned.
[[nodiscard]] std::vector<Field> fields_of(Item& item);

// Names used on the command line: login, note, card, identity. parse_type_name also accepts secure_note.
[[nodiscard]] std::string_view type_name(ItemType type) noexcept;
[[nodiscard]] std::optional<ItemType> parse_type_name(std::string_view name) noexcept;

[[nodiscard]] ItemData empty_data(ItemType type);

} // namespace ck::cli
