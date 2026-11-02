#include "commands.hpp"

#include "item_fields.hpp"

#include <cipherkeeper/crypto/secure_buffer.hpp>
#include <cipherkeeper/model/item.hpp>
#include <cipherkeeper/model/item_codec.hpp>
#include <cipherkeeper/model/item_id.hpp>

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ck::cli {

namespace {

constexpr int max_password_attempts = 3;
constexpr std::size_t min_id_prefix = 4;
constexpr std::size_t short_id_length = 8;
constexpr std::string_view mask = "********";

// ---------------------------------------------------------------------------------------------------------------
// Text helpers. Comparisons work on views so titles aren't copied out of secure memory.

char ascii_lower(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    return std::ranges::equal(a, b, {}, ascii_lower, ascii_lower);
}

bool icontains(std::string_view text, std::string_view part) noexcept {
    return part.empty() || !std::ranges::search(text, part, {}, ascii_lower, ascii_lower).empty();
}

bool iless(std::string_view a, std::string_view b) noexcept {
    return std::ranges::lexicographical_compare(a, b, {}, ascii_lower, ascii_lower);
}

bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

std::string_view trim(std::string_view text) noexcept {
    while (!text.empty() && is_space(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && is_space(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

std::string join(Args words) {
    std::string joined;
    for (const std::string& word : words) {
        if (!joined.empty()) {
            joined += ' ';
        }
        joined += word;
    }
    return joined;
}

std::string in_quotes(std::string_view text) {
    std::string result = "\"";
    result += text;
    result += '"';
    return result;
}

// Splits an answer into list entries without copying it out of secure memory first.
std::vector<SecureString> split_list(std::string_view text, FieldKind kind) {
    std::vector<SecureString> entries;
    const auto is_separator = [kind](char c) { return kind == FieldKind::comma_list ? c == ',' : is_space(c); };
    while (!text.empty()) {
        const auto end = std::ranges::find_if(text, is_separator);
        const auto length = static_cast<std::size_t>(end - text.begin());
        const std::string_view entry = trim(text.substr(0, length));
        if (!entry.empty()) {
            entries.emplace_back(entry);
        }
        text.remove_prefix(std::min(length + 1, text.size()));
    }
    return entries;
}

std::string join_list(const std::vector<SecureString>& values, FieldKind kind) {
    std::string joined;
    for (const SecureString& value : values) {
        if (!joined.empty()) {
            joined += kind == FieldKind::comma_list ? ", " : " ";
        }
        joined += value.view();
    }
    return joined;
}

std::string short_id(const ItemId& id) {
    return id.to_string().substr(0, short_id_length);
}

Failure usage(const std::string& message) {
    return {Exit::usage, message};
}

// ---------------------------------------------------------------------------------------------------------------
// Prompts

std::string prompt_text(std::string_view label, std::string_view hint = {}) {
    std::string prompt(label);
    if (!hint.empty()) {
        prompt += " [";
        prompt += hint;
        prompt += ']';
    }
    prompt += ": ";
    return prompt;
}

SecureString ask(Console& console, std::string_view prompt, bool secret) {
    std::optional<SecureString> answer = secret ? console.read_secret(prompt) : console.read_line(prompt);
    if (!answer) {
        throw Failure(Exit::failure, "cancelled");
    }
    return std::move(*answer);
}

bool ask_yes(Console& console, std::string_view prompt) {
    const SecureString answer = ask(console, prompt, false);
    const std::string_view text = trim(answer.view());
    return iequals(text, "y") || iequals(text, "yes");
}

SecureBuffer to_buffer(const SecureString& text) {
    return SecureBuffer::copy_of(text.bytes());
}

SecureBuffer ask_new_master_password(Console& console) {
    const SecureString first = ask(console, "New master password: ", true);
    if (first.empty()) {
        throw Failure(Exit::failure, "the master password can't be empty");
    }
    const SecureString second = ask(console, "Confirm new master password: ", true);
    if (first != second) {
        throw Failure(Exit::failure, "the passwords don't match");
    }
    return to_buffer(first);
}

void set_field(const Field& field, SecureString answer) {
    if (field.text != nullptr) {
        *field.text = std::move(answer);
    } else {
        *field.list = split_list(answer.view(), field.kind);
    }
}

void clear_field(const Field& field) {
    if (field.text != nullptr) {
        *field.text = SecureString{};
    } else {
        field.list->clear();
    }
}

// The "Custom field name" loop shared by add and edit. An empty name ends it.
void ask_new_custom_fields(Console& console, Item& item) {
    while (true) {
        SecureString name = ask(console, prompt_text("Custom field name"), false);
        if (trim(name.view()).empty()) {
            return;
        }
        const bool hidden = ask_yes(console, prompt_text("Hidden", "y/N"));
        SecureString value = ask(console, prompt_text("Custom field value"), hidden);
        item.custom_fields.push_back({.name = std::move(name), .value = std::move(value), .hidden = hidden});
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Reading items

// Decodes one item, or reports it and returns std::nullopt if its body is corrupt or unreadable.
std::optional<Item> try_load(Console& console, const Vault& vault, const ItemId& id) {
    try {
        const std::optional<SecureBuffer> body = vault.read_item(id);
        if (!body) {
            return std::nullopt;
        }
        return decode_item(body->bytes());
    } catch (const VaultError& e) {
        if (e.kind() != VaultError::Kind::corrupt) {
            throw;
        }
        console.err("ck: skipping item " + id.to_string() + ": " + e.what() + "\n");
    } catch (const ItemFormatError& e) {
        console.err("ck: skipping item " + id.to_string() + ": " + e.what() + "\n");
    }
    return std::nullopt;
}

// Decodes items one at a time, so a large vault never has every field in secure memory at once.
// Returns false if some item couldn't be read.
bool for_each_item(Console& console, const Vault& vault, const std::function<void(const ItemRecord&, Item&)>& visit) {
    bool all_read = true;
    for (const ItemRecord& record : vault.list_items()) {
        std::optional<Item> item = try_load(console, vault, record.id);
        if (item) {
            visit(record, *item);
        } else {
            all_read = false;
        }
    }
    return all_read;
}

Item load_item(const Vault& vault, const ItemId& id) {
    const std::optional<SecureBuffer> body = vault.read_item(id);
    if (!body) {
        throw Failure(Exit::failure, "item " + id.to_string() + " no longer exists");
    }
    return decode_item(body->bytes());
}

struct Match {
    ItemId id;
    SecureString title;
};

// Resolves a query as described in cli.hpp.
ItemId find_item(Console& console, const Vault& vault, Args words) {
    const std::string query = join(words);
    std::string id_query = query;
    std::ranges::transform(id_query, id_query.begin(), ascii_lower);

    std::vector<Match> by_id;
    std::vector<Match> by_title;
    std::vector<Match> by_part;
    (void)for_each_item(console, vault, [&](const ItemRecord& record, Item& item) {
        if (query.size() >= min_id_prefix && record.id.to_string().starts_with(id_query)) {
            by_id.push_back({.id = record.id, .title = std::move(item.title)});
        } else if (iequals(item.title.view(), query)) {
            by_title.push_back({.id = record.id, .title = std::move(item.title)});
        } else if (icontains(item.title.view(), query)) {
            by_part.push_back({.id = record.id, .title = std::move(item.title)});
        }
    });

    const std::vector<Match>& matches = !by_id.empty() ? by_id : !by_title.empty() ? by_title : by_part;
    if (matches.empty()) {
        throw Failure(Exit::failure, "no item matches " + in_quotes(query));
    }
    if (matches.size() > 1) {
        std::string message = in_quotes(query) + " matches " + std::to_string(matches.size()) + " items:\n";
        for (const Match& match : matches) {
            message += "  " + short_id(match.id) + "  ";
            message += match.title.view();
            message += '\n';
        }
        message += "Use more of the title, or the ID.";
        throw Failure(Exit::failure, message);
    }
    return matches.front().id;
}

void print_field(Console& console, Item& item, std::string_view name) {
    const std::string title(item.title.view());
    for (const Field& field : fields_of(item)) {
        if (field.name != name) {
            continue;
        }
        if (field.empty()) {
            throw Failure(Exit::failure, "the " + std::string(name) + " field of " + in_quotes(title) + " is empty");
        }
        if (field.text != nullptr) {
            console.out(field.text->view());
            console.out("\n");
        } else {
            for (const SecureString& value : *field.list) {
                console.out(value.view());
                console.out("\n");
            }
        }
        return;
    }
    for (const CustomField& custom : item.custom_fields) {
        if (custom.name.view() == name) {
            if (custom.value.empty()) {
                throw Failure(Exit::failure,
                              "the " + std::string(name) + " field of " + in_quotes(title) + " is empty");
            }
            console.out(custom.value.view());
            console.out("\n");
            return;
        }
    }
    throw Failure(Exit::failure, in_quotes(title) + " has no field named " + in_quotes(name));
}

void print_item(Console& console, const ItemId& id, Item& item, bool show) {
    console.out("ID: " + id.to_string() + "\n");
    console.out("Type: " + std::string(type_name(item.type())) + "\n");
    const auto line = [&](std::string_view label, std::string_view value, bool secret) {
        console.out(label);
        console.out(": ");
        console.out(secret && !show ? mask : value);
        console.out("\n");
    };
    for (const Field& field : fields_of(item)) {
        if (field.empty()) {
            continue;
        }
        if (field.text != nullptr) {
            line(field.label, field.text->view(), field.secret);
        } else {
            line(field.label, join_list(*field.list, field.kind), field.secret);
        }
    }
    for (const CustomField& custom : item.custom_fields) {
        line(custom.name.view(), custom.value.view(), custom.hidden);
    }
}

// Asks for each field with its current value as the hint. Empty keeps a field, "-" clears it.
void edit_fields(Console& console, Item& item) {
    for (const Field& field : fields_of(item)) {
        std::string hint;
        if (field.secret) {
            hint = field.empty() ? "" : mask;
        } else if (field.text != nullptr) {
            hint = field.text->view();
        } else {
            hint = join_list(*field.list, field.kind);
        }
        SecureString answer = ask(console, prompt_text(field.label, hint), field.secret);
        if (answer.empty()) {
            continue;
        }
        const bool clear = answer.view() == "-";
        if (field.text == &item.title && (clear || trim(answer.view()).empty())) {
            throw Failure(Exit::failure, "the title can't be empty");
        }
        if (clear) {
            clear_field(field);
        } else {
            set_field(field, std::move(answer));
        }
    }
}

// Asks for a new value for each existing custom field. Empty keeps it, "-" removes it.
void edit_custom_fields(Console& console, Item& item) {
    std::vector<CustomField> kept;
    for (CustomField& custom : item.custom_fields) {
        const std::string hint =
            custom.hidden ? std::string(custom.value.empty() ? "" : mask) : std::string(custom.value.view());
        const std::string label = "Value of " + in_quotes(custom.name.view());
        SecureString answer = ask(console, prompt_text(label, hint), custom.hidden);
        if (answer.view() == "-") {
            continue;
        }
        if (!answer.empty()) {
            custom.value = std::move(answer);
        }
        kept.push_back(std::move(custom));
    }
    item.custom_fields = std::move(kept);
}

} // namespace

// -------------------------------------------------------------------------------------------------------------------
// Context

Vault& Context::vault() {
    if (!vault_) {
        vault_ = unlock();
    }
    return *vault_;
}

void Context::unlock_again() {
    vault_ = unlock();
}

Vault Context::unlock() const {
    std::error_code ignored;
    if (!std::filesystem::exists(vault_path_, ignored)) {
        throw Failure(Exit::failure, "there's no vault at " + path_to_utf8(vault_path_) +
                                         ". Run 'ck init' to create one, or pass --vault PATH.");
    }
    for (int attempt = 1; attempt <= max_password_attempts; ++attempt) {
        const SecureString password = ask(console(), "Master password: ", true);
        std::optional<Vault> opened = Vault::open(vault_path_, to_buffer(password));
        if (opened) {
            return std::move(*opened);
        }
        if (attempt < max_password_attempts) {
            console().err("Wrong master password, try again.\n");
        }
    }
    throw Failure(Exit::wrong_password, "wrong master password");
}

// -------------------------------------------------------------------------------------------------------------------
// Commands

Exit init_command(Context& ctx, Args args) {
    if (!args.empty()) {
        throw usage("init takes no arguments");
    }
    const std::filesystem::path& path = ctx.vault_path();
    std::error_code ignored;
    if (std::filesystem::exists(path, ignored)) {
        throw Failure(Exit::failure, "a vault already exists at " + path_to_utf8(path));
    }
    const SecureBuffer password = ask_new_master_password(ctx.console());
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }
    (void)Vault::create(path, password, ctx.settings().kdf);
    ctx.console().err("Created a new vault at " + path_to_utf8(path) + "\n");
    return Exit::ok;
}

Exit add_command(Context& ctx, Args args) {
    if (args.size() != 1) {
        throw usage("usage: ck add <login|note|card|identity>");
    }
    const std::optional<ItemType> type = parse_type_name(args[0]);
    if (!type) {
        throw usage("unknown item type " + in_quotes(args[0]) + "; use login, note, card or identity");
    }

    Vault& vault = ctx.vault();
    Console& console = ctx.console();
    Item item{.data = empty_data(*type)};
    for (const Field& field : fields_of(item)) {
        SecureString answer = ask(console, prompt_text(field.label), field.secret);
        if (field.text == &item.title && trim(answer.view()).empty()) {
            throw Failure(Exit::failure, "a title is required");
        }
        set_field(field, std::move(answer));
    }
    ask_new_custom_fields(console, item);

    const ItemId id = vault.add_item(encode_item(item).bytes());
    console.err("Added " + in_quotes(item.title.view()) + "\n");
    console.out(id.to_string() + "\n");
    return Exit::ok;
}

Exit list_command(Context& ctx, Args args) {
    std::optional<ItemType> type;
    std::vector<std::string> words;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--type") {
            if (i + 1 == args.size()) {
                throw usage("--type needs a type");
            }
            type = parse_type_name(args[++i]);
            if (!type) {
                throw usage("unknown item type " + in_quotes(args[i]));
            }
        } else if (args[i].starts_with("--")) {
            throw usage("unknown option " + args[i]);
        } else {
            words.push_back(args[i]);
        }
    }
    const std::string query = join(words);

    struct Row {
        ItemId id;
        ItemType type;
        SecureString title;
    };
    std::vector<Row> rows;
    const bool all_read = for_each_item(ctx.console(), ctx.vault(), [&](const ItemRecord& record, Item& item) {
        if ((!type || item.type() == *type) && icontains(item.title.view(), query)) {
            rows.push_back({.id = record.id, .type = item.type(), .title = std::move(item.title)});
        }
    });
    std::ranges::stable_sort(rows, [](const Row& a, const Row& b) { return iless(a.title.view(), b.title.view()); });

    for (const Row& row : rows) {
        std::string prefix = short_id(row.id) + "  ";
        prefix += type_name(row.type);
        prefix.resize(short_id_length + 2 + std::string_view("identity").size() + 2, ' ');
        ctx.console().out(prefix);
        ctx.console().out(row.title.view());
        ctx.console().out("\n");
    }
    return all_read ? Exit::ok : Exit::failure;
}

Exit get_command(Context& ctx, Args args) {
    bool show = false;
    std::optional<std::string> field;
    std::vector<std::string> words;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--show") {
            show = true;
        } else if (args[i] == "--field") {
            if (i + 1 == args.size()) {
                throw usage("--field needs a field name");
            }
            field = args[++i];
        } else if (args[i].starts_with("--")) {
            throw usage("unknown option " + args[i]);
        } else {
            words.push_back(args[i]);
        }
    }
    if (words.empty()) {
        throw usage("usage: ck get [--show] [--field NAME] <query>");
    }

    const Vault& vault = ctx.vault();
    const ItemId id = find_item(ctx.console(), vault, words);
    Item item = load_item(vault, id);
    if (field) {
        print_field(ctx.console(), item, *field);
    } else {
        print_item(ctx.console(), id, item, show);
    }
    return Exit::ok;
}

Exit edit_command(Context& ctx, Args args) {
    if (args.empty()) {
        throw usage("usage: ck edit <query>");
    }
    Vault& vault = ctx.vault();
    Console& console = ctx.console();
    const ItemId id = find_item(console, vault, args);
    Item item = load_item(vault, id);

    // Nothing is written until every answer is in.
    edit_fields(console, item);
    edit_custom_fields(console, item);
    ask_new_custom_fields(console, item);

    vault.update_item(id, encode_item(item).bytes());
    console.err("Updated " + in_quotes(item.title.view()) + "\n");
    return Exit::ok;
}

Exit rm_command(Context& ctx, Args args) {
    bool confirmed = false;
    std::vector<std::string> words;
    for (const std::string& arg : args) {
        if (arg == "--yes" || arg == "-y") {
            confirmed = true;
        } else if (arg.starts_with("--")) {
            throw usage("unknown option " + arg);
        } else {
            words.push_back(arg);
        }
    }
    if (words.empty()) {
        throw usage("usage: ck rm [--yes] <query>");
    }

    Vault& vault = ctx.vault();
    Console& console = ctx.console();
    const ItemId id = find_item(console, vault, words);
    const std::string title(load_item(vault, id).title.view());
    if (!confirmed && !ask_yes(console, prompt_text("Delete " + in_quotes(title), "y/N"))) {
        throw Failure(Exit::failure, "nothing was deleted");
    }
    (void)vault.remove_item(id);
    console.err("Deleted " + in_quotes(title) + "\n");
    return Exit::ok;
}

Exit change_master_command(Context& ctx, Args args) {
    if (!args.empty()) {
        throw usage("change-master takes no arguments");
    }
    // Inside unlock the vault is already open, but whoever is at the keyboard must still know the current password.
    if (ctx.in_session()) {
        ctx.unlock_again();
    }
    Vault& vault = ctx.vault();
    const SecureBuffer password = ask_new_master_password(ctx.console());
    vault.change_master_password(password, ctx.settings().kdf);
    ctx.console().err("Changed the master password\n");
    return Exit::ok;
}

// -------------------------------------------------------------------------------------------------------------------
// Paths are UTF-8 on the command line on every platform.

std::filesystem::path path_from_utf8(std::string_view text) {
    std::u8string utf8;
    utf8.reserve(text.size());
    std::ranges::transform(text, std::back_inserter(utf8), [](char c) { return static_cast<char8_t>(c); });
    return {utf8};
}

std::string path_to_utf8(const std::filesystem::path& path) {
    const std::u8string utf8 = path.u8string();
    std::string text;
    text.reserve(utf8.size());
    std::ranges::transform(utf8, std::back_inserter(text), [](char8_t c) { return static_cast<char>(c); });
    return text;
}

} // namespace ck::cli
