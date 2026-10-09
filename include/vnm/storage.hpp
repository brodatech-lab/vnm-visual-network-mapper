#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vnm/model.hpp"

namespace vnm {

/// Persistent store for scans and diffing history.
///
/// The production backend is SQLite (see docs/architecture.md). The skeleton
/// keeps the interface stable while the backend is wired up; the default
/// location is ~/.config/vnm/storage.db.
class Storage {
public:
    explicit Storage(std::string path);

    /// Default DB path: $XDG_CONFIG_HOME/vnm/storage.db or ~/.config/vnm/...
    [[nodiscard]] static std::string default_path();

    /// Open (and create) the database. Returns false and sets *error on failure.
    bool open(std::string* error = nullptr);

    /// Persist a scan; returns the assigned id (>0) or 0 on failure.
    std::int64_t save_scan(const Scan& scan, std::string* error = nullptr);

    /// Load every stored scan (most recent first).
    [[nodiscard]] std::vector<Scan> list_scans(std::string* error = nullptr) const;

    /// Backend availability (false until SQLite is linked in).
    [[nodiscard]] static bool backend_available() noexcept;

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
    bool open_{false};
};

} // namespace vnm
