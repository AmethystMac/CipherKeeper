#pragma once

#include <cipherkeeper/crypto/crypto.hpp>
#include <cipherkeeper/crypto/secure_string.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The ck command-line front end. It lives apart from main() so tests can drive it through a scripted Console.
//
//   ck [--vault PATH] <command> [arguments]
//
//   init                                 create a new vault (parent directories are created)
//   unlock                               unlock once, then run commands typed at a "ck> " prompt until
//                                        lock, exit, quit or end of input. Errors are reported and the
//                                        session continues, except a wrong password in change-master,
//                                        which locks it.
//   add <type>                           add an item: login, note, card or identity
//   list [--type TYPE] [query]           short ID, type and title of each item whose title contains the query,
//                                        sorted by title
//   get [--show] [--field NAME] <query>  show an item, with secret fields masked unless --show
//   edit <query>                         change an item field by field
//   rm [--yes] <query>                   delete an item, asking first unless --yes
//   change-master                        change the master password; asks for the current one even inside unlock
//   help, version
//
// Without --vault, Settings::default_vault is used.
//
// Secrets never come from arguments, since those end up in shell history and process lists. The master password and
// every secret field (password, TOTP secret, card number, security code, hidden custom field values) are read with
// Console::read_secret. Everything else is read with Console::read_line.
//
// A query picks one item. Words are joined with single spaces, then compared ignoring ASCII case, in this order of
// preference: items whose ID starts with the query (at least 4 characters), items whose title equals it, items whose
// title contains it. The first rule with any match decides; it must match exactly one item.
//
// Prompts are "Label: " or "Label [hint]: ", with a quoted name after the label where one is needed
// ("Delete \"Bank\" [y/N]: "). The labels are:
//   master password:  Master password, New master password, Confirm new master password
//   every item:       Title, then the type's fields, then Category, Tags (comma-separated), Notes
//   login:            Username, Password, URLs (space-separated), TOTP secret
//   card:             Cardholder name, Brand, Number, Expiry, Security code
//   identity:         First name, Middle name, Last name, Company, Email, Phone, Address line 1, Address line 2,
//                     City, Region, Postal code, Country
//   custom fields:    Custom field name (empty to finish), Hidden [y/N], Custom field value; repeated
//   edit:             the same labels with the current value as the hint (never for secret fields), then
//                     Value of "NAME" for each existing custom field, then the custom field loop for new ones.
//                     An empty answer keeps a field, "-" clears it (or removes a custom field).
//   rm:               Delete "TITLE" [y/N]
//
// `get --field NAME` prints only that field's value, one line per entry for URLs and tags. NAME is one of title,
// notes, category, tags, username, password, urls, totp_secret, cardholder_name, brand, number, expiry,
// security_code, first_name, middle_name, last_name, company, email, phone, address_line1, address_line2, city,
// region, postal_code, country, or else a custom field's name. A field that's empty or missing is an error.
namespace ck::cli {

enum class Exit : std::uint8_t {
    ok = 0,
    failure = 1,        // the command ran and failed: no such item, vault errors, cancelled input
    usage = 2,          // bad command line
    wrong_password = 3, // the master password was wrong three times
};

// Where ck reads and writes. Prompts and secrets go through here so tests can script them and check which prompts
// were secret. read_line and read_secret return std::nullopt at end of input, which cancels the command.
class Console {
  public:
    Console() = default;
    Console(const Console&) = delete;
    Console& operator=(const Console&) = delete;
    Console(Console&&) = delete;
    Console& operator=(Console&&) = delete;
    virtual ~Console() = default;

    virtual void out(std::string_view text) = 0; // results (stdout)
    virtual void err(std::string_view text) = 0; // errors and status (stderr)
    [[nodiscard]] virtual std::optional<SecureString> read_line(std::string_view prompt) = 0;
    [[nodiscard]] virtual std::optional<SecureString> read_secret(std::string_view prompt) = 0; // no echo
};

struct Settings {
    std::filesystem::path default_vault;
    crypto::KdfParams kdf; // for init and change-master
};

// Runs one ck invocation. `args` excludes the program name. Never throws: errors are printed to Console::err, and
// their messages never contain secrets.
[[nodiscard]] Exit run(std::span<const std::string> args, Console& console, const Settings& settings) noexcept;

// Splits a line typed at the unlock prompt into words. Whitespace separates words and double quotes group them
// (`get "My Bank"`, `a"b c"d` is one word). Returns std::nullopt for an unterminated quote.
[[nodiscard]] std::optional<std::vector<std::string>> split_words(std::string_view line);

} // namespace ck::cli
