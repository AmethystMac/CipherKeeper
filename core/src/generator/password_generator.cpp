#include "cipherkeeper/generator/password_generator.hpp"

#include "cipherkeeper/crypto/secure_buffer.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ck {

namespace {

constexpr std::string_view lowercase_chars = "abcdefghijklmnopqrstuvwxyz";
constexpr std::string_view uppercase_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view digit_chars = "0123456789";
constexpr std::string_view symbol_chars = R"(!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)";
constexpr std::string_view ambiguous_chars = "Il1O0|";

// The chosen sets, each without the look-alike characters if asked. These are public alphabets, not secrets.
std::vector<std::string> chosen_sets(const PasswordOptions& options) {
    const std::array<std::pair<bool, std::string_view>, 4> all{{
        {options.lowercase, lowercase_chars},
        {options.uppercase, uppercase_chars},
        {options.digits, digit_chars},
        {options.symbols, symbol_chars},
    }};
    std::vector<std::string> sets;
    for (const auto& [chosen, chars] : all) {
        if (!chosen) {
            continue;
        }
        std::string set;
        std::ranges::copy_if(chars, std::back_inserter(set), [&](char c) {
            return !options.exclude_ambiguous || ambiguous_chars.find(c) == std::string_view::npos;
        });
        sets.push_back(std::move(set));
    }
    return sets;
}

} // namespace

SecureString generate_password(const PasswordOptions& options) {
    const std::vector<std::string> sets = chosen_sets(options);
    if (sets.empty()) {
        throw std::invalid_argument("generate_password: no character set chosen");
    }
    if (options.length == 0 || options.length > PasswordOptions::max_length) {
        throw std::invalid_argument("generate_password: length must be between 1 and 1024");
    }
    if (options.length < sets.size()) {
        throw std::invalid_argument("generate_password: length is shorter than the number of character sets");
    }

    std::string pool;
    for (const std::string& set : sets) {
        pool += set;
    }
    const auto pool_size = static_cast<std::uint32_t>(pool.size());

    // Draw every character uniformly from the whole pool and keep the first candidate that has every chosen set.
    // Rejection keeps every valid password equally likely (filling one slot per set first would favour small sets
    // such as digits). Rejected candidates are overwritten in place, and the buffer is wiped when it goes out of
    // scope. Even the worst case (length 4, all sets) needs only about 13 draws on average.
    SecureBuffer candidate(options.length);
    const std::string_view text(reinterpret_cast<const char*>(candidate.data()), candidate.size());
    const auto has_every_set = [&] {
        return std::ranges::all_of(
            sets, [&](const std::string& set) { return text.find_first_of(set) != std::string_view::npos; });
    };
    while (true) {
        for (std::byte& b : candidate.bytes()) {
            // randombytes_uniform: CSPRNG output in [0, pool_size) without modulo bias.
            b = static_cast<std::byte>(pool[randombytes_uniform(pool_size)]);
        }
        if (has_every_set()) {
            return SecureString(text);
        }
    }
}

// eff_large_wordlist() is defined in eff_large_wordlist.cpp.

SecureString generate_passphrase(const PassphraseOptions& options) {
    if (options.word_count < PassphraseOptions::min_words || options.word_count > PassphraseOptions::max_words) {
        throw std::invalid_argument("generate_passphrase: word count must be between 4 and 20");
    }

    const std::span<const std::string_view> words = eff_large_wordlist();
    const auto word_total = static_cast<std::uint32_t>(words.size());
    const std::size_t longest = std::ranges::max(words, {}, [](std::string_view word) { return word.size(); }).size();

    // Write straight into a SecureBuffer big enough for the longest possible result, then copy the used part into
    // the SecureString; the scratch buffer is wiped when it goes out of scope. Only the chosen words' text is
    // secret, so nothing else (no index list, no std::string) holds it.
    SecureBuffer scratch((options.word_count * longest) + (options.word_count - 1));
    std::size_t used = 0;
    const auto append = [&](std::string_view text) {
        std::ranges::copy(std::as_bytes(std::span(text)), scratch.bytes().subspan(used).begin());
        used += text.size();
    };
    for (std::size_t i = 0; i < options.word_count; ++i) {
        if (i != 0) {
            append(passphrase_separator);
        }
        // randombytes_uniform: CSPRNG output in [0, 7776) without modulo bias.
        append(words[randombytes_uniform(word_total)]);
    }
    return SecureString(std::string_view(reinterpret_cast<const char*>(scratch.data()), used));
}

} // namespace ck
