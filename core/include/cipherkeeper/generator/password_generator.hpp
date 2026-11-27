#pragma once

#include "cipherkeeper/crypto/secure_string.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace ck {

// Which characters a generated password may use, and how long it is.
//
// The character sets (all ASCII, none overlap):
//   lowercase  abcdefghijklmnopqrstuvwxyz
//   uppercase  ABCDEFGHIJKLMNOPQRSTUVWXYZ
//   digits     0123456789
//   symbols    !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~   (the 32 printable ASCII punctuation marks, no space)
//
// exclude_ambiguous removes the look-alike characters  I l 1 O 0 |  from whichever sets are chosen.
struct PasswordOptions {
    static constexpr std::size_t max_length = 1024;

    std::size_t length = 20;
    bool lowercase = true;
    bool uppercase = true;
    bool digits = true;
    bool symbols = true;
    bool exclude_ambiguous = false;
};

// Returns a random password of exactly `options.length` characters, drawn only from the chosen sets and containing
// at least one character from each of them. Every such password is equally likely: characters are picked with
// randombytes_uniform (no modulo bias), and a candidate that misses a chosen set is overwritten and redrawn.
//
// Throws std::invalid_argument if no set is chosen, or if the length is 0, larger than max_length, or smaller than
// the number of chosen sets.
[[nodiscard]] SecureString generate_password(const PasswordOptions& options = {});

// How many words a generated passphrase has. Words are always joined by a single space (passphrase_separator), the
// usual passphrase format in other password managers; the separator can't be changed.
struct PassphraseOptions {
    static constexpr std::size_t min_words = 4;
    static constexpr std::size_t max_words = 20;

    std::size_t word_count = 8; // about 103 bits (log2(7776) = 12.9 bits per word)
};

inline constexpr std::string_view passphrase_separator = " ";

// The EFF large wordlist (https://www.eff.org/dice, CC BY 3.0 US): 7776 distinct words in the file's order (sorted),
// each 3 to 9 characters of a-z and '-'. No word contains a space. Kept in src/generator/eff_large_wordlist.cpp, a
// copy of core/data/eff_large_wordlist.txt.
[[nodiscard]] std::span<const std::string_view> eff_large_wordlist() noexcept;

// Returns `options.word_count` words from eff_large_wordlist() joined by single spaces, e.g.
// "walrus bucket ambush dimmer oxidize tulip mango velvet". Each word is picked independently with
// randombytes_uniform (no modulo bias), so words may repeat and every passphrase is equally likely. The text is
// built inside a SecureBuffer.
//
// Throws std::invalid_argument if the word count is below min_words or above max_words.
[[nodiscard]] SecureString generate_passphrase(const PassphraseOptions& options = {});

} // namespace ck
