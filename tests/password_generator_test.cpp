#include <cipherkeeper/crypto/secure_string.hpp>
#include <cipherkeeper/generator/password_generator.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

using ck::generate_password;
using ck::PasswordOptions;
using ck::SecureString;

namespace {

// The character sets as the header specifies them.
constexpr std::string_view lowercase = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view digits = "0123456789";
constexpr std::string_view symbols = R"(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)";
constexpr std::string_view ambiguous = "Il1O0|";

bool contains_any(std::string_view text, std::string_view set) {
    return text.find_first_of(set) != std::string_view::npos;
}

bool only_from(std::string_view text, std::string_view allowed) {
    return text.find_first_not_of(allowed) == std::string_view::npos;
}

std::string without(std::string_view set, std::string_view removed) {
    std::string out;
    std::ranges::copy_if(set, std::back_inserter(out),
                         [&](char c) { return removed.find(c) == std::string_view::npos; });
    return out;
}

} // namespace

static_assert(std::is_same_v<decltype(generate_password()), SecureString>);

TEST_CASE("generator: the character sets match the spec") {
    CHECK(lowercase.size() == 26);
    CHECK(uppercase.size() == 26);
    CHECK(digits.size() == 10);
    CHECK(symbols.size() == 32);
}

TEST_CASE("generator: default options give 20 characters from all four sets") {
    const PasswordOptions defaults;
    CHECK(defaults.length == 20);
    CHECK(defaults.lowercase);
    CHECK(defaults.uppercase);
    CHECK(defaults.digits);
    CHECK(defaults.symbols);
    CHECK_FALSE(defaults.exclude_ambiguous);

    const SecureString password = generate_password();
    const std::string_view text = password.view();
    REQUIRE(text.size() == 20);
    CHECK(contains_any(text, lowercase));
    CHECK(contains_any(text, uppercase));
    CHECK(contains_any(text, digits));
    CHECK(contains_any(text, symbols));
}

TEST_CASE("generator: the requested length is honoured") {
    const std::size_t length = GENERATE(std::size_t{4}, std::size_t{5}, std::size_t{64}, PasswordOptions::max_length);
    const SecureString password = generate_password({.length = length});
    CHECK(password.size() == length);
}

TEST_CASE("generator: a single set allows a single character") {
    const SecureString password =
        generate_password({.length = 1, .uppercase = false, .digits = false, .symbols = false});
    REQUIRE(password.size() == 1);
    CHECK(only_from(password.view(), lowercase));
}

TEST_CASE("generator: every chosen set appears, even at the shortest legal length") {
    for (int run = 0; run < 500; ++run) {
        const SecureString password = generate_password({.length = 4});
        const std::string_view text = password.view();
        REQUIRE(text.size() == 4);
        REQUIRE(contains_any(text, lowercase));
        REQUIRE(contains_any(text, uppercase));
        REQUIRE(contains_any(text, digits));
        REQUIRE(contains_any(text, symbols));
    }
}

TEST_CASE("generator: sets that are turned off never appear") {
    SECTION("digits only") {
        for (int run = 0; run < 50; ++run) {
            const SecureString password =
                generate_password({.length = 64, .lowercase = false, .uppercase = false, .symbols = false});
            REQUIRE(only_from(password.view(), digits));
        }
    }
    SECTION("no symbols") {
        const std::string allowed = std::string(lowercase) + std::string(uppercase) + std::string(digits);
        for (int run = 0; run < 50; ++run) {
            const SecureString password = generate_password({.length = 64, .symbols = false});
            REQUIRE(only_from(password.view(), allowed));
            REQUIRE(contains_any(password.view(), lowercase));
            REQUIRE(contains_any(password.view(), uppercase));
            REQUIRE(contains_any(password.view(), digits));
        }
    }
    SECTION("symbols and uppercase only") {
        const std::string allowed = std::string(uppercase) + std::string(symbols);
        for (int run = 0; run < 50; ++run) {
            const SecureString password = generate_password({.length = 64, .lowercase = false, .digits = false});
            REQUIRE(only_from(password.view(), allowed));
        }
    }
}

TEST_CASE("generator: exclude_ambiguous drops the look-alike characters") {
    for (int run = 0; run < 200; ++run) {
        const SecureString password = generate_password({.length = 64, .exclude_ambiguous = true});
        REQUIRE_FALSE(contains_any(password.view(), ambiguous));
    }
}

TEST_CASE("generator: every allowed character can appear") {
    // 200 x 128 characters from a pool of at most 94: each one is expected about 270 times, so a character that
    // never shows up means the set is wrong, not bad luck.
    const auto all_seen = [](const PasswordOptions& options, std::string_view pool) {
        std::string seen;
        for (int run = 0; run < 200; ++run) {
            const SecureString password = generate_password(options);
            seen.append(password.view());
        }
        return std::ranges::all_of(pool, [&](char c) { return seen.find(c) != std::string::npos; });
    };

    SECTION("all sets") {
        const std::string pool =
            std::string(lowercase) + std::string(uppercase) + std::string(digits) + std::string(symbols);
        CHECK(all_seen({.length = 128}, pool));
    }
    SECTION("all sets without the ambiguous characters") {
        const std::string pool = without(
            std::string(lowercase) + std::string(uppercase) + std::string(digits) + std::string(symbols), ambiguous);
        CHECK(pool.size() == 94 - ambiguous.size());
        CHECK(all_seen({.length = 128, .exclude_ambiguous = true}, pool));
    }
}

TEST_CASE("generator: two passwords differ") {
    const SecureString a = generate_password();
    const SecureString b = generate_password();
    CHECK_FALSE(a == b);
}

TEST_CASE("generator: impossible settings are rejected") {
    SECTION("no set chosen") {
        CHECK_THROWS_AS(generate_password({.lowercase = false, .uppercase = false, .digits = false, .symbols = false}),
                        std::invalid_argument);
    }
    SECTION("length 0") {
        CHECK_THROWS_AS(generate_password({.length = 0}), std::invalid_argument);
        CHECK_THROWS_AS(generate_password({.length = 0, .uppercase = false, .digits = false, .symbols = false}),
                        std::invalid_argument);
    }
    SECTION("too short to hold one of each chosen set") {
        CHECK_THROWS_AS(generate_password({.length = 3}), std::invalid_argument);
        CHECK_THROWS_AS(generate_password({.length = 1, .digits = false, .symbols = false}), std::invalid_argument);
    }
    SECTION("longer than the maximum") {
        CHECK_THROWS_AS(generate_password({.length = PasswordOptions::max_length + 1}), std::invalid_argument);
    }
}
