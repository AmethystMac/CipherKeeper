#include "cipherkeeper/model/item_codec.hpp"

#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>

// Item body format v1
// -------------------
// The plaintext that Vault encrypts for one item. All integers are little-endian.
//
//   magic        4 bytes  "CKIT"
//   version      u8       1
//   item type    u8       ItemType (1 login, 2 secure note, 3 card, 4 identity)
//   field count  u32      number of fields that follow; the body must end right after the last one
//   fields       tag (u8) | payload length (u32) | payload
//
// Every payload is UTF-8 text except custom fields, whose payload is
//   flags (u8, bit 0 = hidden, other bits 0) | name length (u32) | name | value (the rest).
//
// Tags 0x01-0x0F are shared by all item types; each type has its own range after that. A single-value tag may appear
// at most once. Repeatable tags (item tags, URLs, custom fields) keep their order. A tag that doesn't belong to the
// item's type, or an unknown tag, makes the body malformed: adding fields means bumping the version.
//
// The field count catches a body cut off between two fields, which length prefixes alone would not.

namespace ck {

namespace {

constexpr std::array<std::byte, 4> magic{std::byte{'C'}, std::byte{'K'}, std::byte{'I'}, std::byte{'T'}};
constexpr std::uint8_t format_version = 1;
constexpr std::size_t header_size = magic.size() + 1 + 1 + 4;
constexpr std::size_t field_header_size = 1 + 4;

namespace tag {
constexpr std::uint8_t title = 0x01;
constexpr std::uint8_t notes = 0x02;
constexpr std::uint8_t category = 0x03;
constexpr std::uint8_t item_tag = 0x04;     // repeatable
constexpr std::uint8_t custom_field = 0x05; // repeatable
constexpr std::uint8_t url = 0x12;          // repeatable, logins only
} // namespace tag

constexpr std::uint8_t custom_field_hidden = 0x01;

// Maps a tag to a single-value text field of T.
template <typename T> struct FieldDef {
    std::uint8_t tag;
    SecureString T::*member;
};

constexpr std::array<FieldDef<Item>, 3> common_fields{{
    {tag::title, &Item::title},
    {tag::notes, &Item::notes},
    {tag::category, &Item::category},
}};

constexpr std::array<FieldDef<LoginData>, 3> login_fields{{
    {0x10, &LoginData::username},
    {0x11, &LoginData::password},
    {0x13, &LoginData::totp_secret},
}};

constexpr std::array<FieldDef<CardData>, 5> card_fields{{
    {0x20, &CardData::cardholder_name},
    {0x21, &CardData::brand},
    {0x22, &CardData::number},
    {0x23, &CardData::expiry},
    {0x24, &CardData::security_code},
}};

constexpr std::array<FieldDef<IdentityData>, 12> identity_fields{{
    {0x30, &IdentityData::first_name},
    {0x31, &IdentityData::middle_name},
    {0x32, &IdentityData::last_name},
    {0x33, &IdentityData::company},
    {0x34, &IdentityData::email},
    {0x35, &IdentityData::phone},
    {0x36, &IdentityData::address_line1},
    {0x37, &IdentityData::address_line2},
    {0x38, &IdentityData::city},
    {0x39, &IdentityData::region},
    {0x3A, &IdentityData::postal_code},
    {0x3B, &IdentityData::country},
}};

std::span<const FieldDef<LoginData>> fields_of(const LoginData& /*data*/) {
    return login_fields;
}
std::span<const FieldDef<SecureNoteData>> fields_of(const SecureNoteData& /*data*/) {
    return {};
}
std::span<const FieldDef<CardData>> fields_of(const CardData& /*data*/) {
    return card_fields;
}
std::span<const FieldDef<IdentityData>> fields_of(const IdentityData& /*data*/) {
    return identity_fields;
}

template <typename T> SecureString* find_field(std::span<const FieldDef<T>> defs, T& owner, std::uint8_t field_tag) {
    for (const FieldDef<T>& def : defs) {
        if (def.tag == field_tag) {
            return &(owner.*def.member);
        }
    }
    return nullptr;
}

[[noreturn]] void malformed(const char* what) {
    throw ItemFormatError(ItemFormatError::Kind::malformed, std::string("item body is malformed: ") + what);
}

std::string_view as_text(std::span<const std::byte> bytes) noexcept {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

std::array<std::byte, 4> le32(std::size_t value) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("item field is too large to encode");
    }
    const auto v = static_cast<std::uint32_t>(value);
    return {static_cast<std::byte>(v & 0xffU), static_cast<std::byte>((v >> 8U) & 0xffU),
            static_cast<std::byte>((v >> 16U) & 0xffU), static_cast<std::byte>((v >> 24U) & 0xffU)};
}

using Parts = std::initializer_list<std::span<const std::byte>>;

// Calls emit(tag, parts) for every field of `item` in canonical order. A field's payload is its parts joined.
template <typename Emit> void for_each_field(const Item& item, const Emit& emit) {
    for (const FieldDef<Item>& def : common_fields) {
        const SecureString& value = item.*def.member;
        if (!value.empty()) {
            emit(def.tag, Parts{value.bytes()});
        }
    }
    for (const SecureString& item_tag : item.tags) {
        emit(tag::item_tag, Parts{item_tag.bytes()});
    }
    for (const CustomField& field : item.custom_fields) {
        const std::array<std::byte, 1> flags{field.hidden ? std::byte{custom_field_hidden} : std::byte{0}};
        const std::array<std::byte, 4> name_size = le32(field.name.size());
        emit(tag::custom_field, Parts{flags, name_size, field.name.bytes(), field.value.bytes()});
    }
    std::visit(
        [&emit](const auto& data) {
            for (const auto& def : fields_of(data)) {
                const SecureString& value = data.*def.member;
                if (!value.empty()) {
                    emit(def.tag, Parts{value.bytes()});
                }
            }
            if constexpr (std::is_same_v<std::decay_t<decltype(data)>, LoginData>) {
                for (const SecureString& url : data.urls) {
                    emit(tag::url, Parts{url.bytes()});
                }
            }
        },
        item.data);
}

std::size_t payload_size(Parts parts) {
    std::size_t size = 0;
    for (const std::span<const std::byte> part : parts) {
        size += part.size();
    }
    return size;
}

class Writer {
  public:
    explicit Writer(std::span<std::byte> out) noexcept : out_(out) {}

    void put(std::span<const std::byte> bytes) {
        std::ranges::copy(bytes, out_.subspan(pos_, bytes.size()).begin());
        pos_ += bytes.size();
    }
    void put_u8(std::uint8_t value) { put(std::array{static_cast<std::byte>(value)}); }

    [[nodiscard]] std::size_t position() const noexcept { return pos_; }

  private:
    std::span<std::byte> out_;
    std::size_t pos_ = 0;
};

// Bounds-checked reads; running past the end throws ItemFormatError.
class Reader {
  public:
    explicit Reader(std::span<const std::byte> in) noexcept : in_(in) {}

    std::span<const std::byte> take(std::size_t size) {
        if (size > in_.size() - pos_) {
            malformed("truncated");
        }
        const std::span<const std::byte> bytes = in_.subspan(pos_, size);
        pos_ += size;
        return bytes;
    }
    std::span<const std::byte> rest() { return take(in_.size() - pos_); }
    std::uint8_t u8() { return std::to_integer<std::uint8_t>(take(1)[0]); }
    std::uint32_t u32() {
        const std::span<const std::byte> b = take(4);
        return std::to_integer<std::uint32_t>(b[0]) | (std::to_integer<std::uint32_t>(b[1]) << 8U) |
               (std::to_integer<std::uint32_t>(b[2]) << 16U) | (std::to_integer<std::uint32_t>(b[3]) << 24U);
    }
    [[nodiscard]] bool at_end() const noexcept { return pos_ == in_.size(); }

  private:
    std::span<const std::byte> in_;
    std::size_t pos_ = 0;
};

void set_once(SecureString& field, std::uint8_t field_tag, std::span<const std::byte> payload, std::bitset<256>& seen) {
    if (seen.test(field_tag)) {
        malformed("duplicate field");
    }
    seen.set(field_tag);
    field = SecureString(as_text(payload));
}

CustomField decode_custom_field(std::span<const std::byte> payload) {
    Reader reader(payload);
    const std::uint8_t flags = reader.u8();
    if (flags > custom_field_hidden) {
        malformed("unknown custom field flags");
    }
    const std::span<const std::byte> name = reader.take(reader.u32());
    const std::span<const std::byte> value = reader.rest();
    return {.name = SecureString(as_text(name)),
            .value = SecureString(as_text(value)),
            .hidden = flags == custom_field_hidden};
}

void apply_field(Item& item, std::uint8_t field_tag, std::span<const std::byte> payload, std::bitset<256>& seen) {
    if (SecureString* field = find_field<Item>(common_fields, item, field_tag)) {
        set_once(*field, field_tag, payload, seen);
        return;
    }
    if (field_tag == tag::item_tag) {
        item.tags.emplace_back(as_text(payload));
        return;
    }
    if (field_tag == tag::custom_field) {
        item.custom_fields.push_back(decode_custom_field(payload));
        return;
    }
    const bool handled = std::visit(
        [&](auto& data) {
            if (SecureString* field = find_field(fields_of(data), data, field_tag)) {
                set_once(*field, field_tag, payload, seen);
                return true;
            }
            if constexpr (std::is_same_v<std::decay_t<decltype(data)>, LoginData>) {
                if (field_tag == tag::url) {
                    data.urls.emplace_back(as_text(payload));
                    return true;
                }
            }
            return false;
        },
        item.data);
    if (!handled) {
        malformed("unknown field for this item type");
    }
}

ItemData empty_data(std::uint8_t type) {
    switch (type) {
    case static_cast<std::uint8_t>(ItemType::login):
        return LoginData{};
    case static_cast<std::uint8_t>(ItemType::secure_note):
        return SecureNoteData{};
    case static_cast<std::uint8_t>(ItemType::card):
        return CardData{};
    case static_cast<std::uint8_t>(ItemType::identity):
        return IdentityData{};
    default:
        malformed("unknown item type");
    }
}

} // namespace

SecureBuffer encode_item(const Item& item) {
    std::size_t size = header_size;
    std::size_t count = 0;
    for_each_field(item, [&](std::uint8_t /*field_tag*/, Parts parts) {
        const std::size_t payload = payload_size(parts);
        (void)le32(payload); // rejects oversized fields before anything is written
        size += field_header_size + payload;
        ++count;
    });

    SecureBuffer body(size);
    Writer writer(body.bytes());
    writer.put(magic);
    writer.put_u8(format_version);
    writer.put_u8(static_cast<std::uint8_t>(item.type()));
    writer.put(le32(count));
    for_each_field(item, [&writer](std::uint8_t field_tag, Parts parts) {
        writer.put_u8(field_tag);
        writer.put(le32(payload_size(parts)));
        for (const std::span<const std::byte> part : parts) {
            writer.put(part);
        }
    });
    if (writer.position() != body.size()) {
        throw std::logic_error("item encoder size mismatch");
    }
    return body;
}

Item decode_item(std::span<const std::byte> body) {
    Reader reader(body);
    if (!std::ranges::equal(reader.take(magic.size()), magic)) {
        malformed("not an item body");
    }
    const std::uint8_t version = reader.u8();
    if (version > format_version) {
        throw ItemFormatError(ItemFormatError::Kind::unsupported_version,
                              "item was written by a newer CipherKeeper version");
    }
    if (version != format_version) {
        malformed("bad format version");
    }

    Item item;
    item.data = empty_data(reader.u8());
    // The count only bounds the loop; a huge count in a short body fails on the first missing field.
    const std::uint32_t count = reader.u32();
    std::bitset<256> seen;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint8_t field_tag = reader.u8();
        const std::span<const std::byte> payload = reader.take(reader.u32());
        apply_field(item, field_tag, payload, seen);
    }
    if (!reader.at_end()) {
        malformed("trailing bytes");
    }
    return item;
}

} // namespace ck
