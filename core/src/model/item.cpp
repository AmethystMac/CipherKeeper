#include "cipherkeeper/model/item.hpp"

#include <array>
#include <utility>
#include <variant>

namespace ck {

namespace {

constexpr std::array<std::pair<ItemType, std::string_view>, 4> type_names{{
    {ItemType::login, "login"},
    {ItemType::secure_note, "secure_note"},
    {ItemType::card, "card"},
    {ItemType::identity, "identity"},
}};

template <typename T> std::vector<T> clone_all(const std::vector<T>& values) {
    std::vector<T> copies;
    copies.reserve(values.size());
    for (const T& value : values) {
        copies.push_back(value.clone());
    }
    return copies;
}

} // namespace

std::string_view to_string(ItemType type) noexcept {
    for (const auto& [value, name] : type_names) {
        if (value == type) {
            return name;
        }
    }
    return "unknown";
}

std::optional<ItemType> parse_item_type(std::string_view name) noexcept {
    for (const auto& [value, known] : type_names) {
        if (known == name) {
            return value;
        }
    }
    return std::nullopt;
}

CustomField CustomField::clone() const {
    return {.name = name.clone(), .value = value.clone(), .hidden = hidden};
}

LoginData LoginData::clone() const {
    return {.username = username.clone(),
            .password = password.clone(),
            .urls = clone_all(urls),
            .totp_secret = totp_secret.clone()};
}

CardData CardData::clone() const {
    return {.cardholder_name = cardholder_name.clone(),
            .brand = brand.clone(),
            .number = number.clone(),
            .expiry = expiry.clone(),
            .security_code = security_code.clone()};
}

IdentityData IdentityData::clone() const {
    return {.first_name = first_name.clone(),
            .middle_name = middle_name.clone(),
            .last_name = last_name.clone(),
            .company = company.clone(),
            .email = email.clone(),
            .phone = phone.clone(),
            .address_line1 = address_line1.clone(),
            .address_line2 = address_line2.clone(),
            .city = city.clone(),
            .region = region.clone(),
            .postal_code = postal_code.clone(),
            .country = country.clone()};
}

ItemType Item::type() const noexcept {
    // holds_alternative can't throw, unlike std::visit.
    static_assert(std::variant_size_v<ItemData> == 4, "add the new item type here");
    if (std::holds_alternative<LoginData>(data)) {
        return ItemType::login;
    }
    if (std::holds_alternative<SecureNoteData>(data)) {
        return ItemType::secure_note;
    }
    if (std::holds_alternative<CardData>(data)) {
        return ItemType::card;
    }
    return ItemType::identity;
}

Item Item::clone() const {
    return {.title = title.clone(),
            .notes = notes.clone(),
            .category = category.clone(),
            .tags = clone_all(tags),
            .custom_fields = clone_all(custom_fields),
            .data = std::visit([](const auto& d) -> ItemData { return d.clone(); }, data)};
}

} // namespace ck
