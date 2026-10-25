#include "prx/libc/include/Api.hpp"
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#include "prx/libc/include/General.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"

namespace {
struct GuestEnvironment {
    std::mutex mutex;
    char* empty[1]{};
    char** fallback = empty;
    char*** storage = &fallback;
    std::list<std::unique_ptr<std::string>> owned;
    std::unique_ptr<char*[]> published;
};

GuestEnvironment& Environment() {
    static GuestEnvironment state;
    return state;
}

bool Matches(const char* entry, std::string_view name) {
    const char* separator = std::strchr(entry, '=');
    return separator && std::string_view(entry, separator - entry) == name;
}

char* Find(GuestEnvironment& environment, std::string_view name) {
    auto* entries = *environment.storage;
    if (entries == nullptr) return nullptr;
    for (; *entries != nullptr; ++entries)
        if (Matches(*entries, name)) return *entries + name.size() + 1;
    return nullptr;
}

std::vector<char*> Entries(GuestEnvironment& environment) {
    std::vector<char*> entries;
    if (auto* current = *environment.storage)
        for (; *current != nullptr; ++current) entries.push_back(*current);
    return entries;
}

void Publish(GuestEnvironment& environment, const std::vector<char*>& entries, std::unique_ptr<std::string> owned = {}) {
    auto published = std::make_unique<char*[]>(entries.size() + 1);
    std::copy(entries.begin(), entries.end(), published.get());
    if (owned) environment.owned.push_back(std::move(owned));
    environment.published.swap(published);
    *environment.storage = environment.published.get();
    environment.owned.remove_if([&entries](const auto& value) {
        const auto start = reinterpret_cast<std::uintptr_t>(value->data());
        return std::none_of(entries.begin(), entries.end(), [start, size = value->size()](const char* entry) {
            const auto address = reinterpret_cast<std::uintptr_t>(entry);
            return address >= start && address - start <= size;
        });
    });
}

void Replace(std::vector<char*>& entries, std::string_view name, char* replacement) {
    auto found = std::find_if(entries.begin(), entries.end(), [name](const char* entry) { return Matches(entry, name); });
    if (found == entries.end()) {
        entries.push_back(replacement);
        return;
    }
    *found = replacement;
    entries.erase(std::remove_if(std::next(found), entries.end(), [name](const char* entry) { return Matches(entry, name); }), entries.end());
}
bool ValidEnvironmentName(const char* name) {
    return name && *name && !std::strchr(name, '=');
}
int EnvironmentError(int error) { errno = error; return -1; }
}

extern "C" {
void BindGuestEnvironment_nid_no_patch(char*** storage) {
    auto& environment = Environment();
    std::lock_guard lock(environment.mutex);
    if (storage == environment.storage) return;
    if (storage == nullptr) {
        environment.fallback = *environment.storage;
        environment.storage = &environment.fallback;
    } else {
        *storage = *environment.storage;
        environment.storage = storage;
    }
}

bool CopyGuestEnvironment_nid_no_patch(const char* name, std::string& value) {
    if (!ValidEnvironmentName(name)) return false;
    auto& environment = Environment();
    std::lock_guard lock(environment.mutex);
    if (const char* found = Find(environment, name)) {
        value = found;
        return true;
    }
    return false;
}

char* APS5_VABI getenv_nid_postfix(const char* name) {
    if (!ValidEnvironmentName(name)) { errno = 22; return nullptr; }
    try {
        auto& environment = Environment();
        std::lock_guard lock(environment.mutex);
        return Find(environment, name);
    } catch (const std::bad_alloc&) { errno = 12; return nullptr; }
}

int APS5_VABI setenv_nid_postfix(const char* name, const char* value, int overwrite) {
    if (!ValidEnvironmentName(name) || !value) return EnvironmentError(22);
    try {
        auto& environment = Environment();
        std::lock_guard lock(environment.mutex);
        if (!overwrite && Find(environment, name)) return 0;
        const std::string key(name);
        auto owned = std::make_unique<std::string>(key + '=' + value);
        auto entries = Entries(environment);
        Replace(entries, key, owned->data());
        Publish(environment, entries, std::move(owned));
        return 0;
    } catch (const std::bad_alloc&) { return EnvironmentError(12); }
}

int APS5_VABI unsetenv_nid_postfix(const char* name) {
    if (!ValidEnvironmentName(name)) return EnvironmentError(22);
    try {
        auto& environment = Environment();
        std::lock_guard lock(environment.mutex);
        const std::string key(name);
        auto entries = Entries(environment);
        const auto removed = std::erase_if(entries, [&key](const char* entry) { return Matches(entry, key); });
        if (removed != 0) Publish(environment, entries);
        return 0;
    } catch (const std::bad_alloc&) { return EnvironmentError(12); }
}

int APS5_VABI putenv_nid_postfix(char* text) {
    const char* separator = text ? std::strchr(text, '=') : nullptr;
    if (!separator || separator == text) return EnvironmentError(22);
    try {
        auto& environment = Environment();
        std::lock_guard lock(environment.mutex);
        const std::string key(text, separator - text);
        auto entries = Entries(environment);
        Replace(entries, key, text);
        Publish(environment, entries);
        return 0;
    } catch (const std::bad_alloc&) { return EnvironmentError(12); }
}
}
