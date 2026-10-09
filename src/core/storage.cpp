#include "vnm/storage.hpp"

#include <cstdlib>

namespace vnm {

Storage::Storage(std::string path) : path_(std::move(path)) {}

std::string Storage::default_path() {
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME")) {
        if (*xdg != '\0') {
            return std::string(xdg) + "/vnm/storage.db";
        }
    }
    if (const char* home = std::getenv("HOME")) {
        if (*home != '\0') {
            return std::string(home) + "/.config/vnm/storage.db";
        }
    }
    return "./storage.db";
}

bool Storage::backend_available() noexcept {
    // SQLite is wired in a later milestone (requires libsqlite3 headers).
    return false;
}

bool Storage::open(std::string* error) {
    if (!backend_available()) {
        if (error != nullptr) {
            *error = "storage backend not linked yet (SQLite milestone pending)";
        }
        return false;
    }
    open_ = true;
    return true;
}

std::int64_t Storage::save_scan(const Scan&, std::string* error) {
    if (!open_ && !open(error)) {
        return 0;
    }
    return 0;
}

std::vector<Scan> Storage::list_scans(std::string* error) const {
    if (!backend_available() && error != nullptr) {
        *error = "storage backend not linked yet (SQLite milestone pending)";
    }
    return {};
}

} // namespace vnm
