#include "cli.hpp"
#include "test_util.hpp"

#include <cipherkeeper/model/item.hpp>
#include <cipherkeeper/model/item_codec.hpp>
#include <cipherkeeper/storage/vault.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <deque>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using ck::Item;
using ck::ItemId;
using ck::SecureString;
using ck::Vault;
using ck::cli::Exit;
using ck::test::secret;
using ck::test::TempDir;

namespace {

constexpr std::string_view master = "throwaway-master-password";

// A console that answers prompts by label: the prompt text up to the first ':', '[', '"' or '>', trimmed. Each label
// has a queue of answers, where std::nullopt means end of input. A label that was never given answers gets "", and
// one whose answers have run out gets end of input, so loops (the unlock prompt, the custom field loop) terminate.
class ScriptedConsole final : public ck::cli::Console {
  public:
    struct Prompt {
        std::string label;
        std::string text;
        bool secret = false;
    };

    void answer(const std::string& label, std::initializer_list<std::optional<std::string>> values) {
        auto& queue = answers_[label];
        queue.insert(queue.end(), values.begin(), values.end());
    }

    void out(std::string_view text) override { out_ += text; }
    void err(std::string_view text) override { err_ += text; }
    std::optional<SecureString> read_line(std::string_view prompt) override { return next(prompt, false); }
    std::optional<SecureString> read_secret(std::string_view prompt) override { return next(prompt, true); }

    [[nodiscard]] std::vector<Prompt> prompts_for(std::string_view label) const {
        std::vector<Prompt> found;
        std::ranges::copy_if(prompts_, std::back_inserter(found), [&](const Prompt& p) { return p.label == label; });
        return found;
    }
    [[nodiscard]] bool asked(std::string_view label) const { return !prompts_for(label).empty(); }
    // True if the label was asked at least once and never with echo.
    [[nodiscard]] bool asked_secretly(std::string_view label) const {
        const auto found = prompts_for(label);
        return !found.empty() && std::ranges::all_of(found, [](const Prompt& p) { return p.secret; });
    }
    [[nodiscard]] bool printed(std::string_view text) const {
        return out_.find(text) != std::string::npos || err_.find(text) != std::string::npos;
    }

    [[nodiscard]] const std::vector<Prompt>& prompts() const noexcept { return prompts_; }
    [[nodiscard]] const std::string& output() const noexcept { return out_; }
    [[nodiscard]] const std::string& errors() const noexcept { return err_; }

  private:
    static std::string label_of(std::string_view prompt) {
        const std::size_t end = prompt.find_first_of(":[\">");
        std::string_view label = prompt.substr(0, end);
        while (!label.empty() && label.back() == ' ') {
            label.remove_suffix(1);
        }
        return std::string(label);
    }

    std::optional<SecureString> next(std::string_view prompt, bool is_secret) {
        if (prompts_.size() > 500) {
            throw std::runtime_error("too many prompts; the command is probably looping");
        }
        const std::string label = label_of(prompt);
        prompts_.push_back({.label = label, .text = std::string(prompt), .secret = is_secret});
        const auto it = answers_.find(label);
        if (it == answers_.end()) {
            return SecureString{};
        }
        if (it->second.empty()) {
            return std::nullopt;
        }
        std::optional<std::string> value = std::move(it->second.front());
        it->second.pop_front();
        if (!value) {
            return std::nullopt;
        }
        return SecureString(*value);
    }

    std::map<std::string, std::deque<std::optional<std::string>>, std::less<>> answers_;
    std::vector<Prompt> prompts_;
    std::string out_;
    std::string err_;
};

struct Cli {
    TempDir dir;
    std::filesystem::path vault = dir.path() / "test.ckvault";
    ck::cli::Settings settings{.default_vault = dir.path() / "default" / "vault.ckvault", .kdf = ck::min_vault_kdf};

    // Runs ck with --vault pointing at `vault`.
    Exit run(ScriptedConsole& console, std::vector<std::string> args) const {
        args.insert(args.begin(), {"--vault", vault.string()});
        return run_raw(console, args);
    }
    Exit run_raw(ScriptedConsole& console, const std::vector<std::string>& args) const {
        return ck::cli::run(args, console, settings);
    }

    // Setup and checks go through the core API, not the CLI under test.
    void make_vault() const { (void)Vault::create(vault, secret(master), ck::min_vault_kdf); }
    [[nodiscard]] Vault open() const {
        std::optional<Vault> opened = Vault::open(vault, secret(master));
        REQUIRE(opened.has_value());
        return std::move(*opened);
    }
    [[nodiscard]] ItemId store(const Item& item) const { return open().add_item(encode_item(item).bytes()); }
    [[nodiscard]] Item load(const ItemId& id) const {
        const std::optional<ck::SecureBuffer> body = open().read_item(id);
        REQUIRE(body.has_value());
        return ck::decode_item(body->bytes());
    }
    [[nodiscard]] std::vector<Item> load_all() const {
        const Vault opened = open();
        std::vector<Item> items;
        for (const ck::ItemRecord& record : opened.list_items()) {
            const std::optional<ck::SecureBuffer> body = opened.read_item(record.id);
            REQUIRE(body.has_value());
            items.push_back(ck::decode_item(body->bytes()));
        }
        return items;
    }
};

SecureString s(std::string_view text) {
    return SecureString(text);
}

Item make_login(std::string_view title, std::string_view username, std::string_view password) {
    Item item{.title = s(title), .data = ck::LoginData{.username = s(username), .password = s(password)}};
    return item;
}

Item make_note(std::string_view title, std::string_view text) {
    return Item{.title = s(title), .notes = s(text), .data = ck::SecureNoteData{}};
}

void answer_master(ScriptedConsole& console) {
    console.answer("Master password", {std::string(master)});
}

std::string short_id(const ItemId& id) {
    return id.to_string().substr(0, 8);
}

} // namespace

// ---------------------------------------------------------------------------------------------------------------
// Command line

TEST_CASE("cli: help and version") {
    const Cli cli;
    ScriptedConsole console;

    SECTION("help prints the commands") {
        REQUIRE(cli.run_raw(console, {"help"}) == Exit::ok);
        for (const char* command : {"init", "unlock", "add", "list", "get", "edit", "rm", "change-master"}) {
            CHECK(console.output().find(command) != std::string::npos);
        }
    }
    SECTION("--help is the same as help") {
        REQUIRE(cli.run_raw(console, {"--help"}) == Exit::ok);
        CHECK(console.output().find("change-master") != std::string::npos);
    }
    SECTION("version") {
        REQUIRE(cli.run_raw(console, {"version"}) == Exit::ok);
        CHECK(console.output().starts_with("ck "));
    }
    SECTION("no command is a usage error") {
        CHECK(cli.run_raw(console, {}) == Exit::usage);
        CHECK_FALSE(console.errors().empty());
    }
}

TEST_CASE("cli: bad command lines are usage errors") {
    const Cli cli;
    ScriptedConsole console;

    SECTION("unknown command") {
        CHECK(cli.run(console, {"frobnicate"}) == Exit::usage);
        CHECK(console.errors().find("frobnicate") != std::string::npos);
    }
    SECTION("--vault without a path") {
        CHECK(cli.run_raw(console, {"--vault"}) == Exit::usage);
    }
    SECTION("add without a type") {
        cli.make_vault();
        CHECK(cli.run(console, {"add"}) == Exit::usage);
    }
    SECTION("add with an unknown type") {
        cli.make_vault();
        CHECK(cli.run(console, {"add", "spaceship"}) == Exit::usage);
    }
    SECTION("get, edit and rm need a query") {
        cli.make_vault();
        CHECK(cli.run(console, {"get"}) == Exit::usage);
        CHECK(cli.run(console, {"edit"}) == Exit::usage);
        CHECK(cli.run(console, {"rm"}) == Exit::usage);
    }
    SECTION("list with an unknown type") {
        cli.make_vault();
        CHECK(cli.run(console, {"list", "--type", "spaceship"}) == Exit::usage);
    }
    SECTION("usage errors don't ask for the master password") {
        cli.make_vault();
        (void)cli.run(console, {"add", "spaceship"});
        CHECK_FALSE(console.asked("Master password"));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// init

TEST_CASE("cli: init creates a vault that opens with the new password") {
    const Cli cli;
    ScriptedConsole console;
    console.answer("New master password", {std::string(master)});
    console.answer("Confirm new master password", {std::string(master)});

    REQUIRE(cli.run(console, {"init"}) == Exit::ok);
    CHECK(console.asked_secretly("New master password"));
    CHECK(console.asked_secretly("Confirm new master password"));

    const Vault vault = cli.open();
    CHECK(vault.list_items().empty());
    CHECK(vault.kdf_params() == cli.settings.kdf);
    CHECK_FALSE(console.printed(master));
}

TEST_CASE("cli: init without --vault uses the default path and creates its directory") {
    const Cli cli;
    ScriptedConsole console;
    console.answer("New master password", {std::string(master)});
    console.answer("Confirm new master password", {std::string(master)});

    REQUIRE(cli.run_raw(console, {"init"}) == Exit::ok);
    CHECK(Vault::open(cli.settings.default_vault, secret(master)).has_value());
}

TEST_CASE("cli: init refuses bad passwords and leaves no file") {
    const Cli cli;
    ScriptedConsole console;

    SECTION("confirmation doesn't match") {
        console.answer("New master password", {"first-password"});
        console.answer("Confirm new master password", {"second-password"});
    }
    SECTION("empty password") {
        console.answer("New master password", {""});
        console.answer("Confirm new master password", {""});
    }
    SECTION("end of input") {
        console.answer("New master password", {std::nullopt});
    }

    CHECK(cli.run(console, {"init"}) == Exit::failure);
    CHECK_FALSE(console.errors().empty());
    CHECK_FALSE(std::filesystem::exists(cli.vault));
}

TEST_CASE("cli: init won't overwrite an existing vault") {
    const Cli cli;
    cli.make_vault();
    const ItemId id = cli.store(make_note("Keep me", "still here"));

    ScriptedConsole console;
    console.answer("New master password", {"another-password"});
    console.answer("Confirm new master password", {"another-password"});

    CHECK(cli.run(console, {"init"}) == Exit::failure);
    CHECK(console.errors().find("exists") != std::string::npos);
    CHECK(cli.load(id).title.view() == "Keep me");
}

// ---------------------------------------------------------------------------------------------------------------
// Unlocking

TEST_CASE("cli: the master password is read without echo and never printed") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;
    answer_master(console);

    REQUIRE(cli.run(console, {"list"}) == Exit::ok);
    CHECK(console.asked_secretly("Master password"));
    CHECK_FALSE(console.printed(master));
}

TEST_CASE("cli: a wrong master password is retried up to three times") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;

    SECTION("three wrong attempts") {
        console.answer("Master password", {"wrong-1", "wrong-2", "wrong-3", std::string(master)});
        CHECK(cli.run(console, {"list"}) == Exit::wrong_password);
        CHECK(console.prompts_for("Master password").size() == 3);
        CHECK_FALSE(console.printed("wrong-1"));
    }
    SECTION("a wrong attempt, then the right one") {
        console.answer("Master password", {"wrong-1", std::string(master)});
        CHECK(cli.run(console, {"list"}) == Exit::ok);
    }
    SECTION("end of input cancels") {
        console.answer("Master password", {std::nullopt});
        CHECK(cli.run(console, {"list"}) == Exit::failure);
    }
}

TEST_CASE("cli: commands on a missing vault fail and suggest init") {
    const Cli cli;
    ScriptedConsole console;
    answer_master(console);

    CHECK(cli.run(console, {"list"}) == Exit::failure);
    CHECK(console.errors().find("init") != std::string::npos);
    CHECK_FALSE(console.asked("Master password"));
    CHECK_FALSE(std::filesystem::exists(cli.vault));
}

TEST_CASE("cli: a file that isn't a vault is reported, not unlocked") {
    const Cli cli;
    {
        std::ofstream file(cli.vault, std::ios::binary);
        file << "definitely not a vault";
    }
    ScriptedConsole console;
    answer_master(console);

    CHECK(cli.run(console, {"list"}) == Exit::failure);
    CHECK_FALSE(console.errors().empty());
}

// ---------------------------------------------------------------------------------------------------------------
// add

TEST_CASE("cli: add login stores every field") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;
    answer_master(console);
    console.answer("Title", {"Example"});
    console.answer("Username", {"alice"});
    console.answer("Password", {"pw-123"});
    console.answer("URLs", {"https://example.com  https://login.example.com"});
    console.answer("TOTP secret", {"JBSWY3DPEHPK3PXP"});
    console.answer("Category", {"Web"});
    console.answer("Tags", {"work, personal ,, "});
    console.answer("Notes", {"hello there"});
    console.answer("Custom field name", {"PIN", "Security question", ""});
    console.answer("Hidden", {"y", "n"});
    console.answer("Custom field value", {"1234", "blue"});

    REQUIRE(cli.run(console, {"add", "login"}) == Exit::ok);

    const std::vector<Item> items = cli.load_all();
    REQUIRE(items.size() == 1);
    Item expected{
        .title = s("Example"),
        .notes = s("hello there"),
        .category = s("Web"),
        .data = ck::LoginData{.username = s("alice"), .password = s("pw-123"), .totp_secret = s("JBSWY3DPEHPK3PXP")}};
    std::get<ck::LoginData>(expected.data).urls.push_back(s("https://example.com"));
    std::get<ck::LoginData>(expected.data).urls.push_back(s("https://login.example.com"));
    expected.tags.push_back(s("work"));
    expected.tags.push_back(s("personal"));
    expected.custom_fields.push_back({.name = s("PIN"), .value = s("1234"), .hidden = true});
    expected.custom_fields.push_back({.name = s("Security question"), .value = s("blue"), .hidden = false});
    CHECK(items[0] == expected);

    SECTION("secret fields are read without echo, the rest with echo") {
        CHECK(console.asked_secretly("Password"));
        CHECK(console.asked_secretly("TOTP secret"));
        const auto values = console.prompts_for("Custom field value");
        REQUIRE(values.size() == 2);
        CHECK(values[0].secret);
        CHECK_FALSE(values[1].secret);
        for (const char* label : {"Title", "Username", "URLs", "Category", "Tags", "Notes", "Custom field name"}) {
            CAPTURE(label);
            CHECK_FALSE(console.asked_secretly(label));
        }
    }
    SECTION("the new item's ID is printed, and no secret is") {
        const std::vector<ck::ItemRecord> records = cli.open().list_items();
        REQUIRE(records.size() == 1);
        CHECK(console.output().find(records[0].id.to_string()) != std::string::npos);
        CHECK_FALSE(console.printed("pw-123"));
        CHECK_FALSE(console.printed("1234"));
    }
}

TEST_CASE("cli: add note, card and identity") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;
    answer_master(console);

    SECTION("note") {
        console.answer("Title", {"Wi-Fi"});
        console.answer("Notes", {"network: home, key: abc"});
        REQUIRE(cli.run(console, {"add", "note"}) == Exit::ok);
        const std::vector<Item> items = cli.load_all();
        REQUIRE(items.size() == 1);
        CHECK(items[0] == make_note("Wi-Fi", "network: home, key: abc"));
    }
    SECTION("secure_note is accepted too") {
        console.answer("Title", {"Wi-Fi"});
        REQUIRE(cli.run(console, {"add", "secure_note"}) == Exit::ok);
        REQUIRE(cli.load_all().size() == 1);
        CHECK(cli.load_all()[0].type() == ck::ItemType::secure_note);
    }
    SECTION("card") {
        console.answer("Title", {"Visa"});
        console.answer("Cardholder name", {"Alice Example"});
        console.answer("Brand", {"Visa"});
        console.answer("Number", {"4111111111111111"});
        console.answer("Expiry", {"08/2029"});
        console.answer("Security code", {"123"});
        REQUIRE(cli.run(console, {"add", "card"}) == Exit::ok);

        const std::vector<Item> items = cli.load_all();
        REQUIRE(items.size() == 1);
        const Item expected{.title = s("Visa"),
                            .data = ck::CardData{.cardholder_name = s("Alice Example"),
                                                 .brand = s("Visa"),
                                                 .number = s("4111111111111111"),
                                                 .expiry = s("08/2029"),
                                                 .security_code = s("123")}};
        CHECK(items[0] == expected);
        CHECK(console.asked_secretly("Number"));
        CHECK(console.asked_secretly("Security code"));
        CHECK_FALSE(console.asked_secretly("Cardholder name"));
    }
    SECTION("identity") {
        console.answer("Title", {"Me"});
        console.answer("First name", {"Alice"});
        console.answer("Last name", {"Example"});
        console.answer("Address line 1", {"1 Main St"});
        console.answer("Postal code", {"12345"});
        console.answer("Country", {"US"});
        REQUIRE(cli.run(console, {"add", "identity"}) == Exit::ok);

        const std::vector<Item> items = cli.load_all();
        REQUIRE(items.size() == 1);
        const Item expected{.title = s("Me"),
                            .data = ck::IdentityData{.first_name = s("Alice"),
                                                     .last_name = s("Example"),
                                                     .address_line1 = s("1 Main St"),
                                                     .postal_code = s("12345"),
                                                     .country = s("US")}};
        CHECK(items[0] == expected);
        for (const char* label : {"Middle name", "Company", "Email", "Phone", "Address line 2", "City", "Region"}) {
            CAPTURE(label);
            CHECK(console.asked(label));
        }
    }
}

TEST_CASE("cli: add stores nothing when cancelled or untitled") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;
    answer_master(console);

    SECTION("empty title") {
        console.answer("Title", {""});
    }
    SECTION("end of input partway") {
        console.answer("Title", {"Example"});
        console.answer("Username", {"alice"});
        console.answer("Password", {std::nullopt});
    }

    CHECK(cli.run(console, {"add", "login"}) == Exit::failure);
    CHECK(cli.open().list_items().empty());
}

// ---------------------------------------------------------------------------------------------------------------
// list

TEST_CASE("cli: list shows items sorted by title without secrets") {
    const Cli cli;
    cli.make_vault();
    const ItemId gamma = cli.store(make_login("gamma", "g-user", "gamma-secret"));
    const ItemId alpha = cli.store(make_note("Alpha", "alpha-note-text"));
    const ItemId beta = cli.store(make_login("beta", "b-user", "beta-secret"));

    ScriptedConsole console;
    answer_master(console);
    REQUIRE(cli.run(console, {"list"}) == Exit::ok);

    const std::string& out = console.output();
    const std::size_t a = out.find("Alpha");
    const std::size_t b = out.find("beta");
    const std::size_t g = out.find("gamma");
    REQUIRE(a != std::string::npos);
    REQUIRE(b != std::string::npos);
    REQUIRE(g != std::string::npos);
    CHECK(a < b);
    CHECK(b < g);
    for (const ItemId& id : {alpha, beta, gamma}) {
        CHECK(out.find(short_id(id)) != std::string::npos);
    }
    CHECK(out.find("login") != std::string::npos);
    CHECK(out.find("note") != std::string::npos);
    CHECK_FALSE(console.printed("secret"));
    CHECK_FALSE(console.printed("alpha-note-text"));
}

TEST_CASE("cli: list filters by query and type") {
    const Cli cli;
    cli.make_vault();
    (void)cli.store(make_login("Bank of Example", "u", "p"));
    (void)cli.store(make_note("Bank PINs", "n"));
    (void)cli.store(make_login("Mail", "u", "p"));

    ScriptedConsole console;
    answer_master(console);

    SECTION("query matches titles ignoring case") {
        REQUIRE(cli.run(console, {"list", "bank"}) == Exit::ok);
        CHECK(console.output().find("Bank of Example") != std::string::npos);
        CHECK(console.output().find("Bank PINs") != std::string::npos);
        CHECK(console.output().find("Mail") == std::string::npos);
    }
    SECTION("--type") {
        REQUIRE(cli.run(console, {"list", "--type", "note"}) == Exit::ok);
        CHECK(console.output().find("Bank PINs") != std::string::npos);
        CHECK(console.output().find("Bank of Example") == std::string::npos);
        CHECK(console.output().find("Mail") == std::string::npos);
    }
    SECTION("an empty vault prints nothing") {
        const Cli empty;
        empty.make_vault();
        ScriptedConsole other;
        answer_master(other);
        REQUIRE(empty.run(other, {"list"}) == Exit::ok);
        CHECK(other.output().empty());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// get

TEST_CASE("cli: get masks secrets unless --show") {
    const Cli cli;
    cli.make_vault();
    Item item = make_login("Example", "alice", "pw-123");
    std::get<ck::LoginData>(item.data).urls.push_back(s("https://example.com"));
    std::get<ck::LoginData>(item.data).totp_secret = s("JBSWY3DPEHPK3PXP");
    item.custom_fields.push_back({.name = s("PIN"), .value = s("9876"), .hidden = true});
    item.custom_fields.push_back({.name = s("Colour"), .value = s("blue"), .hidden = false});
    const ItemId id = cli.store(item);

    ScriptedConsole console;
    answer_master(console);

    SECTION("masked") {
        REQUIRE(cli.run(console, {"get", "Example"}) == Exit::ok);
        for (const char* shown : {"Example", "alice", "https://example.com", "Password", "PIN", "blue"}) {
            CAPTURE(shown);
            CHECK(console.output().find(shown) != std::string::npos);
        }
        CHECK(console.output().find(id.to_string()) != std::string::npos);
        CHECK_FALSE(console.printed("pw-123"));
        CHECK_FALSE(console.printed("JBSWY3DPEHPK3PXP"));
        CHECK_FALSE(console.printed("9876"));
    }
    SECTION("--show") {
        REQUIRE(cli.run(console, {"get", "--show", "Example"}) == Exit::ok);
        CHECK(console.output().find("pw-123") != std::string::npos);
        CHECK(console.output().find("JBSWY3DPEHPK3PXP") != std::string::npos);
        CHECK(console.output().find("9876") != std::string::npos);
    }
}

TEST_CASE("cli: get --field prints just the value") {
    const Cli cli;
    cli.make_vault();
    Item item = make_login("Example", "alice", "pw-123");
    std::get<ck::LoginData>(item.data).urls.push_back(s("https://a.example"));
    std::get<ck::LoginData>(item.data).urls.push_back(s("https://b.example"));
    item.custom_fields.push_back({.name = s("PIN"), .value = s("9876"), .hidden = true});
    (void)cli.store(item);

    ScriptedConsole console;
    answer_master(console);

    SECTION("password") {
        REQUIRE(cli.run(console, {"get", "--field", "password", "Example"}) == Exit::ok);
        CHECK(console.output() == "pw-123\n");
    }
    SECTION("urls, one per line") {
        REQUIRE(cli.run(console, {"get", "--field", "urls", "Example"}) == Exit::ok);
        CHECK(console.output() == "https://a.example\nhttps://b.example\n");
    }
    SECTION("a custom field by name") {
        REQUIRE(cli.run(console, {"get", "--field", "PIN", "Example"}) == Exit::ok);
        CHECK(console.output() == "9876\n");
    }
    SECTION("an empty field is an error") {
        CHECK(cli.run(console, {"get", "--field", "totp_secret", "Example"}) == Exit::failure);
        CHECK(console.output().empty());
    }
    SECTION("a field the item type doesn't have is an error") {
        CHECK(cli.run(console, {"get", "--field", "security_code", "Example"}) == Exit::failure);
        CHECK(console.output().empty());
    }
}

TEST_CASE("cli: queries pick one item by ID prefix, exact title or title substring") {
    const Cli cli;
    cli.make_vault();
    const ItemId bank = cli.store(make_login("Bank", "bank-user", "x"));
    (void)cli.store(make_login("Bank Savings", "savings-user", "x"));
    (void)cli.store(make_login("Mail", "mail-user", "x"));

    ScriptedConsole console;
    answer_master(console);
    const auto username_for = [&](std::vector<std::string> query) {
        query.insert(query.begin(), {"get", "--field", "username"});
        REQUIRE(cli.run(console, query) == Exit::ok);
        return console.output();
    };

    SECTION("full ID") {
        CHECK(username_for({bank.to_string()}) == "bank-user\n");
    }
    SECTION("ID prefix, any case") {
        std::string prefix = short_id(bank);
        std::ranges::transform(prefix, prefix.begin(), [](char c) { return static_cast<char>(std::toupper(c)); });
        CHECK(username_for({prefix}) == "bank-user\n");
    }
    SECTION("an exact title beats a substring match") {
        CHECK(username_for({"bank"}) == "bank-user\n");
    }
    SECTION("a unique substring") {
        CHECK(username_for({"sav"}) == "savings-user\n");
    }
    SECTION("several words are joined with spaces") {
        CHECK(username_for({"bank", "savings"}) == "savings-user\n");
    }
}

TEST_CASE("cli: a query that matches nothing or several items fails") {
    const Cli cli;
    cli.make_vault();
    const ItemId one = cli.store(make_login("Bank One", "u1", "x"));
    (void)cli.store(make_login("Bank Two", "u2", "x"));

    ScriptedConsole console;
    answer_master(console);

    SECTION("no match") {
        CHECK(cli.run(console, {"get", "nothing-like-this"}) == Exit::failure);
        CHECK(console.output().empty());
    }
    SECTION("ambiguous, and the candidates are listed") {
        CHECK(cli.run(console, {"get", "bank"}) == Exit::failure);
        CHECK(console.errors().find("Bank One") != std::string::npos);
        CHECK(console.errors().find("Bank Two") != std::string::npos);
        CHECK(console.output().empty());
    }
    SECTION("an ID prefix under 4 characters isn't treated as an ID") {
        CHECK(cli.run(console, {"get", short_id(one).substr(0, 3)}) == Exit::failure);
        CHECK(console.output().empty());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// edit

TEST_CASE("cli: edit keeps, replaces and clears fields") {
    const Cli cli;
    cli.make_vault();
    Item item = make_login("Example", "alice", "pw-123");
    std::get<ck::LoginData>(item.data).urls.push_back(s("https://example.com"));
    item.category = s("Web");
    item.tags.push_back(s("old"));
    item.custom_fields.push_back({.name = s("PIN"), .value = s("1234"), .hidden = true});
    item.custom_fields.push_back({.name = s("Colour"), .value = s("blue"), .hidden = false});
    const ItemId id = cli.store(item);

    ScriptedConsole console;
    answer_master(console);
    console.answer("Title", {""});
    console.answer("Username", {"bob"});
    console.answer("Password", {""});
    console.answer("URLs", {"-"});
    console.answer("Category", {"Personal"});
    console.answer("Tags", {"a, b"});
    console.answer("Value of", {"-", "green"});
    console.answer("Custom field name", {"Recovery code", ""});
    console.answer("Hidden", {"y"});
    console.answer("Custom field value", {"r-555"});

    REQUIRE(cli.run(console, {"edit", "Example"}) == Exit::ok);

    Item expected = make_login("Example", "bob", "pw-123");
    expected.category = s("Personal");
    expected.tags.push_back(s("a"));
    expected.tags.push_back(s("b"));
    expected.custom_fields.push_back({.name = s("Colour"), .value = s("green"), .hidden = false});
    expected.custom_fields.push_back({.name = s("Recovery code"), .value = s("r-555"), .hidden = true});
    CHECK(cli.load(id) == expected);
    CHECK(cli.open().list_items().at(0).revision == 2);

    SECTION("current values are hints for plain fields and never for secret ones") {
        CHECK(console.prompts_for("Username").at(0).text.find("alice") != std::string::npos);
        CHECK(console.prompts_for("Category").at(0).text.find("Web") != std::string::npos);
        CHECK(console.asked_secretly("Password"));
        CHECK_FALSE(console.printed("pw-123"));
        CHECK_FALSE(console.printed("1234"));
        for (const auto& prompt : console.prompts()) {
            CHECK(prompt.text.find("pw-123") == std::string::npos);
            CHECK(prompt.text.find("1234") == std::string::npos);
        }
    }
    SECTION("a hidden custom field's value is asked without echo") {
        const auto values = console.prompts_for("Value of");
        REQUIRE(values.size() == 2);
        CHECK(values[0].secret);
        CHECK(values[0].text.find("PIN") != std::string::npos);
        CHECK_FALSE(values[1].secret);
    }
}

TEST_CASE("cli: edit leaves the item unchanged when it fails") {
    const Cli cli;
    cli.make_vault();
    const ItemId id = cli.store(make_login("Example", "alice", "pw-123"));
    ScriptedConsole console;
    answer_master(console);

    SECTION("clearing the title") {
        console.answer("Title", {"-"});
        CHECK(cli.run(console, {"edit", "Example"}) == Exit::failure);
    }
    SECTION("end of input partway") {
        console.answer("Username", {"bob"});
        console.answer("Password", {std::nullopt});
        CHECK(cli.run(console, {"edit", "Example"}) == Exit::failure);
    }
    SECTION("no match") {
        CHECK(cli.run(console, {"edit", "nothing-like-this"}) == Exit::failure);
    }

    CHECK(cli.load(id) == make_login("Example", "alice", "pw-123"));
    CHECK(cli.open().list_items().at(0).revision == 1);
}

// ---------------------------------------------------------------------------------------------------------------
// rm

TEST_CASE("cli: rm asks before deleting") {
    const Cli cli;
    cli.make_vault();
    (void)cli.store(make_note("Keep", "k"));
    (void)cli.store(make_note("Old", "o"));
    ScriptedConsole console;
    answer_master(console);

    SECTION("yes") {
        console.answer("Delete", {"y"});
        REQUIRE(cli.run(console, {"rm", "Old"}) == Exit::ok);
        CHECK(console.prompts_for("Delete").at(0).text.find("\"Old\"") != std::string::npos);
        const std::vector<Item> items = cli.load_all();
        REQUIRE(items.size() == 1);
        CHECK(items[0].title.view() == "Keep");
    }
    SECTION("anything else keeps it") {
        console.answer("Delete", {""});
        CHECK(cli.run(console, {"rm", "Old"}) == Exit::failure);
        CHECK(cli.load_all().size() == 2);
    }
    SECTION("--yes skips the question") {
        REQUIRE(cli.run(console, {"rm", "--yes", "Old"}) == Exit::ok);
        CHECK_FALSE(console.asked("Delete"));
        CHECK(cli.load_all().size() == 1);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// change-master

TEST_CASE("cli: change-master re-keys the vault and keeps its items") {
    const Cli cli;
    cli.make_vault();
    const ItemId id = cli.store(make_note("Keep", "k"));
    ScriptedConsole console;
    answer_master(console);
    console.answer("New master password", {"brand-new-password"});
    console.answer("Confirm new master password", {"brand-new-password"});

    REQUIRE(cli.run(console, {"change-master"}) == Exit::ok);
    CHECK(console.asked_secretly("New master password"));
    CHECK(console.asked_secretly("Confirm new master password"));
    CHECK_FALSE(console.printed("brand-new-password"));

    CHECK_FALSE(Vault::open(cli.vault, secret(master)).has_value());
    std::optional<Vault> reopened = Vault::open(cli.vault, secret("brand-new-password"));
    REQUIRE(reopened.has_value());
    CHECK(reopened->kdf_params() == cli.settings.kdf);
    CHECK(reopened->read_item(id).has_value());
}

TEST_CASE("cli: change-master keeps the old password when the new one is rejected") {
    const Cli cli;
    cli.make_vault();
    ScriptedConsole console;
    answer_master(console);

    SECTION("mismatch") {
        console.answer("New master password", {"one-password"});
        console.answer("Confirm new master password", {"other-password"});
    }
    SECTION("empty") {
        console.answer("New master password", {""});
        console.answer("Confirm new master password", {""});
    }

    CHECK(cli.run(console, {"change-master"}) == Exit::failure);
    CHECK(Vault::open(cli.vault, secret(master)).has_value());
}

// ---------------------------------------------------------------------------------------------------------------
// unlock

TEST_CASE("cli: unlock runs several commands with one password prompt") {
    const Cli cli;
    cli.make_vault();
    (void)cli.store(make_login("My Bank", "bank-user", "x"));
    ScriptedConsole console;
    answer_master(console);
    console.answer("ck", {"list", "", "get --field username \"My Bank\"", "add note", "list"});
    console.answer("Title", {"Shell note"});

    REQUIRE(cli.run(console, {"unlock"}) == Exit::ok);
    CHECK(console.prompts_for("Master password").size() == 1);
    CHECK(console.output().find("bank-user\n") != std::string::npos);
    CHECK(cli.load_all().size() == 2);
}

TEST_CASE("cli: unlock reports errors and keeps going") {
    const Cli cli;
    cli.make_vault();
    (void)cli.store(make_note("Note", "n"));
    ScriptedConsole console;
    answer_master(console);

    SECTION("unknown commands, init, unlock and bad quoting") {
        console.answer("ck", {"frobnicate", "init", "unlock", "get \"unterminated", "list"});
        REQUIRE(cli.run(console, {"unlock"}) == Exit::ok);
        CHECK(console.errors().find("frobnicate") != std::string::npos);
        CHECK(console.output().find("Note") != std::string::npos);
        CHECK_FALSE(console.asked("New master password"));
        CHECK(console.prompts_for("Master password").size() == 1);
    }
    SECTION("lock, exit and quit end the session") {
        for (const char* word : {"lock", "exit", "quit"}) {
            ScriptedConsole session;
            answer_master(session);
            session.answer("ck", {word, "list"});
            REQUIRE(cli.run(session, {"unlock"}) == Exit::ok);
            CHECK(session.output().find("Note") == std::string::npos);
        }
    }
    SECTION("change-master asks for the current password again and keeps the vault usable") {
        answer_master(console);
        console.answer("ck", {"change-master", "list"});
        console.answer("New master password", {"brand-new-password"});
        console.answer("Confirm new master password", {"brand-new-password"});
        REQUIRE(cli.run(console, {"unlock"}) == Exit::ok);
        CHECK(console.prompts_for("Master password").size() == 2);
        CHECK(console.output().find("Note") != std::string::npos);
        CHECK(Vault::open(cli.vault, secret("brand-new-password")).has_value());
    }
    SECTION("a wrong password in change-master locks the session") {
        console.answer("Master password", {"wrong-1", "wrong-2", "wrong-3"});
        console.answer("ck", {"change-master", "list"});
        CHECK(cli.run(console, {"unlock"}) == Exit::wrong_password);
        CHECK(console.output().find("Note") == std::string::npos);
        CHECK_FALSE(console.asked("New master password"));
        CHECK(Vault::open(cli.vault, secret(master)).has_value());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// split_words

TEST_CASE("cli: split_words") {
    using ck::cli::split_words;
    using Words = std::vector<std::string>;

    CHECK(split_words("") == Words{});
    CHECK(split_words("   ") == Words{});
    CHECK(split_words("list") == Words{"list"});
    CHECK(split_words("  get   --show  bank ") == Words{"get", "--show", "bank"});
    CHECK(split_words("get \"My Bank\"") == Words{"get", "My Bank"});
    CHECK(split_words("a\"b c\"d e") == Words{"ab cd", "e"});
    CHECK(split_words("get \"\"") == Words{"get", ""});
    CHECK(split_words("tab\tseparated") == Words{"tab", "separated"});
    CHECK_FALSE(split_words("get \"unterminated").has_value());
}
