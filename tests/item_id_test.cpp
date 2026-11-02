#include <cipherkeeper/model/item_id.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>

using ck::ItemId;

TEST_CASE("generated item IDs are version 4 UUIDs and differ") {
    const ItemId a = ItemId::generate();
    const ItemId b = ItemId::generate();
    CHECK(a != b);
    CHECK((a.bytes()[6] & std::byte{0xf0}) == std::byte{0x40});
    CHECK((a.bytes()[8] & std::byte{0xc0}) == std::byte{0x80});

    const std::string text = a.to_string();
    REQUIRE(text.size() == 36);
    CHECK(text[14] == '4');
}

TEST_CASE("item IDs round-trip through text") {
    const ItemId id = ItemId::generate();
    const std::optional<ItemId> parsed = ItemId::parse(id.to_string());
    REQUIRE(parsed.has_value());
    CHECK(*parsed == id);
}

TEST_CASE("item ID parsing accepts uppercase and gives lowercase back") {
    const std::optional<ItemId> parsed = ItemId::parse("0123ABCD-4567-4890-ABCD-EF0123456789");
    REQUIRE(parsed.has_value());
    CHECK(parsed->to_string() == "0123abcd-4567-4890-abcd-ef0123456789");
}

TEST_CASE("item ID parsing rejects anything but the canonical form") {
    CHECK_FALSE(ItemId::parse("").has_value());
    CHECK_FALSE(ItemId::parse("0123abcd-4567-4890-abcd-ef012345678").has_value());   // too short
    CHECK_FALSE(ItemId::parse("0123abcd-4567-4890-abcd-ef01234567890").has_value()); // too long
    CHECK_FALSE(ItemId::parse("0123abcd4567-4890-abcd-ef0123456789-").has_value());  // dash moved
    CHECK_FALSE(ItemId::parse("0123abcd-4567-4890-abcd-ef012345678g").has_value());  // not hex
    CHECK_FALSE(ItemId::parse("{123abcd-4567-4890-abcd-ef0123456789").has_value());
}
