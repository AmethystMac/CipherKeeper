#include "item_fields.hpp"

#include <variant>

namespace ck::cli {

namespace {

Field text(std::string_view label, std::string_view name, SecureString& value, bool secret = false) {
    return {.label = label, .name = name, .secret = secret, .kind = FieldKind::text, .text = &value};
}

Field list(std::string_view label, std::string_view name, FieldKind kind, std::vector<SecureString>& values) {
    return {.label = label, .name = name, .kind = kind, .list = &values};
}

void add_type_fields(std::vector<Field>& fields, LoginData& d) {
    fields.push_back(text("Username", "username", d.username));
    fields.push_back(text("Password", "password", d.password, true));
    fields.push_back(list("URLs", "urls", FieldKind::words, d.urls));
    fields.push_back(text("TOTP secret", "totp_secret", d.totp_secret, true));
}

void add_type_fields(std::vector<Field>& /*fields*/, SecureNoteData& /*d*/) {}

void add_type_fields(std::vector<Field>& fields, CardData& d) {
    fields.push_back(text("Cardholder name", "cardholder_name", d.cardholder_name));
    fields.push_back(text("Brand", "brand", d.brand));
    fields.push_back(text("Number", "number", d.number, true));
    fields.push_back(text("Expiry", "expiry", d.expiry));
    fields.push_back(text("Security code", "security_code", d.security_code, true));
}

void add_type_fields(std::vector<Field>& fields, IdentityData& d) {
    fields.push_back(text("First name", "first_name", d.first_name));
    fields.push_back(text("Middle name", "middle_name", d.middle_name));
    fields.push_back(text("Last name", "last_name", d.last_name));
    fields.push_back(text("Company", "company", d.company));
    fields.push_back(text("Email", "email", d.email));
    fields.push_back(text("Phone", "phone", d.phone));
    fields.push_back(text("Address line 1", "address_line1", d.address_line1));
    fields.push_back(text("Address line 2", "address_line2", d.address_line2));
    fields.push_back(text("City", "city", d.city));
    fields.push_back(text("Region", "region", d.region));
    fields.push_back(text("Postal code", "postal_code", d.postal_code));
    fields.push_back(text("Country", "country", d.country));
}

} // namespace

std::vector<Field> fields_of(Item& item) {
    std::vector<Field> fields;
    fields.push_back(text("Title", "title", item.title));
    std::visit([&](auto& data) { add_type_fields(fields, data); }, item.data);
    fields.push_back(text("Category", "category", item.category));
    fields.push_back(list("Tags", "tags", FieldKind::comma_list, item.tags));
    fields.push_back(text("Notes", "notes", item.notes));
    return fields;
}

std::string_view type_name(ItemType type) noexcept {
    switch (type) {
    case ItemType::login:
        return "login";
    case ItemType::secure_note:
        return "note";
    case ItemType::card:
        return "card";
    case ItemType::identity:
        return "identity";
    }
    return "unknown";
}

std::optional<ItemType> parse_type_name(std::string_view name) noexcept {
    if (name == "note") {
        return ItemType::secure_note;
    }
    return parse_item_type(name);
}

ItemData empty_data(ItemType type) {
    switch (type) {
    case ItemType::login:
        return LoginData{};
    case ItemType::secure_note:
        return SecureNoteData{};
    case ItemType::card:
        return CardData{};
    case ItemType::identity:
        return IdentityData{};
    }
    return SecureNoteData{};
}

} // namespace ck::cli
