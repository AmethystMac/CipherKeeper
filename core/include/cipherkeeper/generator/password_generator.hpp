#pragma once

#include "cipherkeeper/crypto/secure_string.hpp"

#include <cstddef>

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

} // namespace ck
