#include <cipherkeeper/crypto/secure_string.hpp>
#include <cipherkeeper/generator/password_generator.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <ios>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

using ck::generate_passphrase;
using ck::generate_password;
using ck::PassphraseOptions;
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

// The EFF large wordlist read straight from the published file ("DDDDD<TAB>word" per line), independent of the copy
// core embeds.
const std::vector<std::string>& eff_words() {
    static const std::vector<std::string> words = [] {
        std::ifstream in(CK_EFF_WORDLIST_PATH, std::ios::binary);
        std::vector<std::string> out;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const std::size_t tab = line.find('\t');
            out.push_back(tab == std::string::npos ? line : line.substr(tab + 1));
        }
        return out;
    }();
    return words;
}

// Word -> its position in the file.
const std::unordered_map<std::string_view, std::size_t>& eff_index() {
    static const std::unordered_map<std::string_view, std::size_t> index = [] {
        std::unordered_map<std::string_view, std::size_t> out;
        const std::vector<std::string>& words = eff_words();
        for (std::size_t i = 0; i < words.size(); ++i) {
            out.emplace(words[i], i);
        }
        return out;
    }();
    return index;
}

bool is_eff_word(std::string_view word) {
    return eff_index().contains(word);
}

// Splits a passphrase at each space. No EFF word contains a space, so this is exact, and a leading, trailing or
// doubled space shows up as an empty part, which is_eff_word rejects.
std::vector<std::string_view> split_words(std::string_view text) {
    std::vector<std::string_view> parts;
    while (true) {
        const std::size_t at = text.find(' ');
        parts.push_back(text.substr(0, at));
        if (at == std::string_view::npos) {
            return parts;
        }
        text.remove_prefix(at + 1);
    }
}

} // namespace

static_assert(std::is_same_v<decltype(generate_password()), SecureString>);
static_assert(std::is_same_v<decltype(generate_passphrase()), SecureString>);

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

TEST_CASE("passphrase: the embedded wordlist is the EFF large wordlist") {
    const std::vector<std::string>& file = eff_words();
    REQUIRE(file.size() == 7776);
    CHECK(file.front() == "abacus");
    CHECK(file.back() == "zoom");

    const auto list = ck::eff_large_wordlist();
    REQUIRE(list.size() == file.size());
    CHECK(std::ranges::equal(list, file));
}

TEST_CASE("passphrase: the wordlist has distinct, sorted words of 3 to 9 characters from a-z and '-'") {
    const auto list = ck::eff_large_wordlist();
    REQUIRE(list.size() == 7776);
    CHECK(std::ranges::is_sorted(list));
    CHECK(std::ranges::adjacent_find(list) == list.end());
    const std::string allowed = std::string(lowercase) + "-";
    CHECK(std::ranges::all_of(
        list, [&](std::string_view word) { return word.size() >= 3 && word.size() <= 9 && only_from(word, allowed); }));
}

TEST_CASE("passphrase: default options give 8 words, and counts are limited to 4-20") {
    const PassphraseOptions defaults;
    CHECK(defaults.word_count == 8);
    CHECK(PassphraseOptions::min_words == 4);
    CHECK(PassphraseOptions::max_words == 20);

    const SecureString passphrase = generate_passphrase();
    const std::vector<std::string_view> words = split_words(passphrase.view());
    REQUIRE(words.size() == 8);
    CHECK(std::ranges::all_of(words, is_eff_word));
}

TEST_CASE("passphrase: words are joined by single spaces") {
    CHECK(ck::passphrase_separator == " ");
    for (int run = 0; run < 100; ++run) {
        const SecureString passphrase = generate_passphrase();
        const std::string_view text = passphrase.view();
        REQUIRE(only_from(text, std::string(lowercase) + "- "));
        REQUIRE(std::ranges::count(text, ' ') == 7);
        REQUIRE_FALSE(text.starts_with(' '));
        REQUIRE_FALSE(text.ends_with(' '));
        REQUIRE(text.find("  ") == std::string_view::npos);
    }
}

TEST_CASE("passphrase: the requested word count is honoured") {
    const std::size_t count = GENERATE(PassphraseOptions::min_words, std::size_t{5}, std::size_t{8}, std::size_t{13},
                                       PassphraseOptions::max_words);
    const SecureString passphrase = generate_passphrase({.word_count = count});
    const std::vector<std::string_view> words = split_words(passphrase.view());
    REQUIRE(words.size() == count);
    CHECK(std::ranges::all_of(words, is_eff_word));
}

TEST_CASE("passphrase: every word is from the list") {
    for (int run = 0; run < 300; ++run) {
        const SecureString passphrase = generate_passphrase({.word_count = PassphraseOptions::max_words});
        const std::vector<std::string_view> words = split_words(passphrase.view());
        REQUIRE(words.size() == PassphraseOptions::max_words);
        for (const std::string_view word : words) {
            REQUIRE(is_eff_word(word));
        }
    }
}

TEST_CASE("passphrase: words come from every part of the list") {
    // The list in 36 blocks of 216 (the first two dice). 1600 words make a block about 44 times as likely as not to
    // be hit, so a missing block means only part of the list is used, not bad luck.
    std::array<bool, 36> seen{};
    for (int run = 0; run < 200; ++run) {
        const SecureString passphrase = generate_passphrase();
        for (const std::string_view word : split_words(passphrase.view())) {
            REQUIRE(is_eff_word(word));
            seen.at(eff_index().at(word) / 216) = true;
        }
    }
    CHECK(std::ranges::all_of(seen, [](bool hit) { return hit; }));
}

TEST_CASE("passphrase: two passphrases differ") {
    const SecureString a = generate_passphrase();
    const SecureString b = generate_passphrase();
    CHECK_FALSE(a == b);
}

TEST_CASE("passphrase: word counts outside 4-20 are rejected") {
    const std::size_t count = GENERATE(std::size_t{0}, std::size_t{1}, PassphraseOptions::min_words - 1,
                                       PassphraseOptions::max_words + 1, std::size_t{100});
    CHECK_THROWS_AS(generate_passphrase({.word_count = count}), std::invalid_argument);
}
