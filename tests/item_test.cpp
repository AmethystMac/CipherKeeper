#include "test_util.hpp"

#include <cipherkeeper/crypto/secure_string.hpp>
#include <cipherkeeper/model/item.hpp>
#include <cipherkeeper/model/item_codec.hpp>
#include <cipherkeeper/storage/vault.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using ck::CardData;
using ck::IdentityData;
using ck::Item;
using ck::ItemFormatError;
using ck::ItemType;
using ck::LoginData;
using ck::SecureNoteData;
using ck::SecureString;

namespace {

SecureString s(std::string_view text) {
    return SecureString(text);
}

std::vector<SecureString> strings(std::initializer_list<std::string_view> texts) {
    std::vector<SecureString> out;
    for (const std::string_view text : texts) {
        out.emplace_back(text);
    }
    return out;
}

// Throwaway sample data only.
Item full_login() {
    Item item;
    item.title = s("Example Mail");
    item.notes = s("Recovery codes are in the safe.");
    item.category = s("Email");
    item.tags = strings({"personal", "2fa"});
    item.custom_fields.push_back({.name = s("PIN"), .value = s("0000"), .hidden = true});
    item.custom_fields.push_back({.name = s("Account no."), .value = s("12-345"), .hidden = false});
    item.data = LoginData{.username = s("alice@example.com"),
                          .password = s("throwaway-Tulip-Orbit"),
                          .urls = strings({"https://mail.example.com", "https://example.com/login"}),
                          .totp_secret = s("JBSWY3DPEHPK3PXP")};
    return item;
}

Item full_card() {
    Item item;
    item.title = s("Travel card");
    item.data = CardData{.cardholder_name = s("Alice Example"),
                         .brand = s("Visa"),
                         .number = s("4111111111111111"),
                         .expiry = s("08/2029"),
                         .security_code = s("123")};
    return item;
}

Item full_identity() {
    Item item;
    item.title = s("Me");
    item.data = IdentityData{.first_name = s("Alice"),
                             .middle_name = s("B."),
                             .last_name = s("Example"),
                             .company = s("Example Ltd"),
                             .email = s("alice@example.com"),
                             .phone = s("+1 555 0100"),
                             .address_line1 = s("1 Example Street"),
                             .address_line2 = s("Flat 2"),
                             .city = s("Springfield"),
                             .region = s("Ohio"),
                             .postal_code = s("12345"),
                             .country = s("US")};
    return item;
}

Item note() {
    Item item;
    item.title = s("Wi-Fi");
    item.notes = s("Network: example\nKey: correct horse battery staple");
    item.data = SecureNoteData{};
    return item;
}

Item round_trip(const Item& item) {
    const ck::SecureBuffer body = ck::encode_item(item);
    return ck::decode_item(body.bytes());
}

auto is_kind(ItemFormatError::Kind kind) {
    return Catch::Matchers::Predicate<ItemFormatError>([kind](const ItemFormatError& e) { return e.kind() == kind; },
                                                       "ItemFormatError of the expected kind");
}

// Builds a body by hand, for inputs the encoder would never produce.
class BodyBuilder {
  public:
    BodyBuilder(std::uint8_t version, std::uint8_t type) {
        bytes_ = {std::byte{'C'}, std::byte{'K'}, std::byte{'I'}, std::byte{'T'}, std::byte{version}, std::byte{type}};
    }
    BodyBuilder& field(std::uint8_t tag, std::span<const std::byte> payload) {
        fields_.push_back(std::byte{tag});
        put_u32(fields_, payload.size());
        fields_.insert(fields_.end(), payload.begin(), payload.end());
        ++count_;
        return *this;
    }
    BodyBuilder& field(std::uint8_t tag, std::string_view text) { return field(tag, ck::test::bytes_of(text)); }
    BodyBuilder& count(std::size_t count) {
        count_override_ = count;
        return *this;
    }
    [[nodiscard]] std::vector<std::byte> build() const {
        std::vector<std::byte> out = bytes_;
        put_u32(out, count_override_.value_or(count_));
        out.insert(out.end(), fields_.begin(), fields_.end());
        return out;
    }

  private:
    static void put_u32(std::vector<std::byte>& out, std::size_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8) {
            out.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
        }
    }

    std::vector<std::byte> bytes_;
    std::vector<std::byte> fields_;
    std::size_t count_ = 0;
    std::optional<std::size_t> count_override_;
};

constexpr std::uint8_t login_type = 1;
constexpr std::uint8_t title_tag = 0x01;

} // namespace

// ---- SecureString -------------------------------------------------------------------------------------------------

TEST_CASE("SecureString holds a copy of its text") {
    std::string source = "hunter2";
    const SecureString secret(source);
    source[0] = 'X';
    CHECK(secret.view() == "hunter2");
    CHECK(secret.size() == 7);

    const SecureString copy = secret.clone();
    CHECK(copy == secret);
    CHECK(copy.view().data() != secret.view().data());
    CHECK_FALSE(SecureString("hunter3") == secret);
    CHECK(SecureString().empty());
    CHECK(SecureString("").empty());
}

// ---- Item types ---------------------------------------------------------------------------------------------------

TEST_CASE("an item's type follows its data") {
    CHECK(full_login().type() == ItemType::login);
    CHECK(note().type() == ItemType::secure_note);
    CHECK(full_card().type() == ItemType::card);
    CHECK(full_identity().type() == ItemType::identity);
    CHECK(Item{}.type() == ItemType::login);
}

TEST_CASE("item type names round-trip") {
    for (const ItemType type : {ItemType::login, ItemType::secure_note, ItemType::card, ItemType::identity}) {
        CHECK(ck::parse_item_type(ck::to_string(type)) == type);
    }
    CHECK_FALSE(ck::parse_item_type("password").has_value());
}

TEST_CASE("clone makes an equal, independent copy") {
    const Item original = full_login();
    Item copy = original.clone();
    CHECK(copy == original);
    std::get<LoginData>(copy.data).password = s("changed");
    CHECK_FALSE(copy == original);
}

// ---- Encoding round trips -----------------------------------------------------------------------------------------

TEST_CASE("every item type round-trips through the codec") {
    CHECK(round_trip(full_login()) == full_login());
    CHECK(round_trip(note()) == note());
    CHECK(round_trip(full_card()) == full_card());
    CHECK(round_trip(full_identity()) == full_identity());
    CHECK(round_trip(Item{}) == Item{});
}

TEST_CASE("the codec keeps the order of repeated fields and the hidden flag") {
    const Item decoded = round_trip(full_login());
    REQUIRE(decoded.tags.size() == 2);
    CHECK(decoded.tags[0].view() == "personal");
    CHECK(decoded.tags[1].view() == "2fa");
    REQUIRE(decoded.custom_fields.size() == 2);
    CHECK(decoded.custom_fields[0].hidden);
    CHECK_FALSE(decoded.custom_fields[1].hidden);
    const auto& login = std::get<LoginData>(decoded.data);
    REQUIRE(login.urls.size() == 2);
    CHECK(login.urls[1].view() == "https://example.com/login");
}

TEST_CASE("the codec preserves arbitrary text exactly") {
    Item item;
    item.title = s("Caf\xC3\xA9 \xE2\x9C\x93 \xF0\x9F\x94\x91"); // UTF-8: é, check mark, key emoji
    item.notes = SecureString(std::string_view("a\0b", 3));      // embedded NUL
    item.tags = strings({""});                                   // empty repeated values are kept
    const Item decoded = round_trip(item);
    CHECK(decoded == item);
    CHECK(decoded.notes.size() == 3);
    CHECK(decoded.tags.size() == 1);
}

TEST_CASE("encoding is deterministic") {
    const ck::SecureBuffer a = ck::encode_item(full_identity());
    const ck::SecureBuffer b = ck::encode_item(full_identity());
    CHECK(ck::test::same_bytes(a.bytes(), b.bytes()));
    const ck::SecureBuffer again = ck::encode_item(ck::decode_item(a.bytes()));
    CHECK(ck::test::same_bytes(a.bytes(), again.bytes()));
}

TEST_CASE("an item survives a vault round trip") {
    const ck::test::TempDir dir;
    ck::Vault vault =
        ck::Vault::create(dir.path() / "test.ckvault", ck::test::secret("throwaway-test-password"), ck::min_vault_kdf);
    const ck::ItemId id = vault.add_item(ck::encode_item(full_login()).bytes());
    const std::optional<ck::SecureBuffer> body = vault.read_item(id);
    REQUIRE(body.has_value());
    CHECK(ck::decode_item(body->bytes()) == full_login());
}

// ---- Malformed bodies ---------------------------------------------------------------------------------------------

TEST_CASE("decode rejects bodies that aren't items") {
    CHECK_THROWS_MATCHES(ck::decode_item({}), ItemFormatError, is_kind(ItemFormatError::Kind::malformed));
    CHECK_THROWS_MATCHES(ck::decode_item(ck::test::bytes_of("CKIX\x01\x01\0\0\0\0")), ItemFormatError,
                         is_kind(ItemFormatError::Kind::malformed));
}

TEST_CASE("decode reports a newer format version as unsupported") {
    CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(2, login_type).build()), ItemFormatError,
                         is_kind(ItemFormatError::Kind::unsupported_version));
    CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(0, login_type).build()), ItemFormatError,
                         is_kind(ItemFormatError::Kind::malformed));
}

TEST_CASE("decode accepts a minimal hand-built body") {
    const Item item = ck::decode_item(BodyBuilder(1, login_type).field(title_tag, "Hand built").build());
    CHECK(item.title.view() == "Hand built");
    CHECK(item.type() == ItemType::login);
}

TEST_CASE("decode rejects structurally invalid bodies") {
    const auto malformed = is_kind(ItemFormatError::Kind::malformed);

    SECTION("unknown item type") {
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, 9).build()), ItemFormatError, malformed);
    }
    SECTION("unknown tag") {
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).field(0x7F, "x").build()), ItemFormatError,
                             malformed);
    }
    SECTION("tag from another item type") {
        const std::uint8_t card_number_tag = 0x22;
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).field(card_number_tag, "4111").build()),
                             ItemFormatError, malformed);
    }
    SECTION("duplicate single-value field") {
        CHECK_THROWS_MATCHES(
            ck::decode_item(BodyBuilder(1, login_type).field(title_tag, "a").field(title_tag, "b").build()),
            ItemFormatError, malformed);
    }
    SECTION("field count larger than the fields present") {
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).field(title_tag, "a").count(2).build()),
                             ItemFormatError, malformed);
    }
    SECTION("huge field count") {
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).count(0xFFFFFFFF).build()), ItemFormatError,
                             malformed);
    }
    SECTION("trailing bytes after the last field") {
        std::vector<std::byte> body = BodyBuilder(1, login_type).field(title_tag, "a").build();
        body.push_back(std::byte{0});
        CHECK_THROWS_MATCHES(ck::decode_item(body), ItemFormatError, malformed);
    }
    SECTION("field length past the end of the body") {
        std::vector<std::byte> body = BodyBuilder(1, login_type).field(title_tag, "abc").build();
        body.pop_back();
        CHECK_THROWS_MATCHES(ck::decode_item(body), ItemFormatError, malformed);
    }
    SECTION("custom field with unknown flags") {
        const std::vector<std::byte> payload{std::byte{0x02}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).field(0x05, payload).build()), ItemFormatError,
                             malformed);
    }
    SECTION("custom field name longer than its payload") {
        const std::vector<std::byte> payload{std::byte{0x00}, std::byte{9}, std::byte{0},
                                             std::byte{0},    std::byte{0}, std::byte{'a'}};
        CHECK_THROWS_MATCHES(ck::decode_item(BodyBuilder(1, login_type).field(0x05, payload).build()), ItemFormatError,
                             malformed);
    }
}

TEST_CASE("decode rejects every truncation of a valid body") {
    const ck::SecureBuffer body = ck::encode_item(full_login());
    for (std::size_t length = 0; length < body.size(); ++length) {
        INFO("length " << length);
        CHECK_THROWS_AS(ck::decode_item(body.bytes().first(length)), ItemFormatError);
    }
}

TEST_CASE("decode never fails in any other way on corrupted bodies") {
    // Each single-byte corruption must either decode or throw ItemFormatError. Under ASan this also proves the
    // decoder never reads outside the body.
    const ck::SecureBuffer original = ck::encode_item(full_login());
    for (std::size_t i = 0; i < original.size(); ++i) {
        for (const std::byte flip : {std::byte{0x01}, std::byte{0x80}, std::byte{0xFF}}) {
            ck::SecureBuffer body = ck::SecureBuffer::copy_of(original.bytes());
            body.bytes()[i] ^= flip;
            INFO("byte " << i);
            try {
                (void)ck::decode_item(body.bytes());
            } catch (const ItemFormatError&) {
                // expected for most corruptions
            }
        }
    }
}
