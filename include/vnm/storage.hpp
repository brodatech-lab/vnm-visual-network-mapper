#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "vnm/diff.hpp"
#include "vnm/model.hpp"

struct sqlite3; // forward declaration (from <sqlite3.h>)

namespace vnm {

/// Lightweight row used by the history view.
struct ScanSummary {
    std::int64_t id{0};
    std::string target;
    std::string started_at;   // unix epoch as text (nmap 'start')
    std::string finished_at;  // unix epoch as text (nmap 'finished')
    std::string nmap_version;
    std::string created_at;   // local DB timestamp (ISO-8601)
    std::size_t host_count{0};
};

/// SQLite-backed persistence for scans and time-travel diffing.
///
/// Default database: $XDG_CONFIG_HOME/vnm/storage.db or ~/.config/vnm/storage.db
class Storage {
public:
    explicit Storage(std::string path);
    ~Storage();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    Storage(Storage&&) = delete;
    Storage& operator=(Storage&&) = delete;

    [[nodiscard]] static std::string default_path();

    /// Open (and create) the database and schema. Returns false + error on failure.
    bool open(std::string* error = nullptr);

    [[nodiscard]] bool is_open() const noexcept;

    /// Persist a full scan (hosts + ports) in a single transaction.
    /// Returns the new scan id (>0) or 0 on failure.
    std::int64_t save_scan(const Scan& scan, std::string* error = nullptr);

    /// All scans, most recent first.
    [[nodiscard]] std::vector<ScanSummary> list_scans(std::string* error = nullptr) const;

    /// Load a complete scan (hosts + ports) by id.
    [[nodiscard]] std::optional<Scan> load_scan(std::int64_t id,
                                                std::string* error = nullptr) const;

    /// Remove a scan and its hosts/ports (cascade). Returns true if a row was deleted.
    bool delete_scan(std::int64_t id, std::string* error = nullptr);

    /// Diff two stored scans by id (`after` vs `before`).
    [[nodiscard]] std::optional<ScanDiff> diff(std::int64_t before_id,
                                               std::int64_t after_id,
                                               std::string* error = nullptr) const;

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
    sqlite3* db_{nullptr};
};

} // namespace vnm
