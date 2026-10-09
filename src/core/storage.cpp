#include "vnm/storage.hpp"

#include <sqlite3.h>

#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>

namespace vnm {
namespace {

constexpr const char* kSchema = R"SQL(
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT    NOT NULL DEFAULT '',
    started_at   TEXT    NOT NULL DEFAULT '',
    finished_at  TEXT    NOT NULL DEFAULT '',
    nmap_version TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    address       TEXT    NOT NULL,
    mac           TEXT    NOT NULL DEFAULT '',
    vendor        TEXT    NOT NULL DEFAULT '',
    hostname      TEXT    NOT NULL DEFAULT '',
    os_name       TEXT    NOT NULL DEFAULT '',
    os_confidence INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'unknown',
    risk          TEXT    NOT NULL DEFAULT 'unknown',
    subnet        TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number    INTEGER NOT NULL DEFAULT 0,
    protocol  TEXT    NOT NULL DEFAULT '',
    state     TEXT    NOT NULL DEFAULT '',
    service   TEXT    NOT NULL DEFAULT '',
    product   TEXT    NOT NULL DEFAULT '',
    version   TEXT    NOT NULL DEFAULT '',
    extrainfo TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_addr ON hosts(address);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
)SQL";

/// RAII wrapper for a prepared statement.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        ok_ = sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) == SQLITE_OK;
    }
    ~Stmt() {
        if (stmt_ != nullptr) {
            sqlite3_finalize(stmt_);
        }
    }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }

    void text(int idx, const std::string& value) {
        sqlite3_bind_text(stmt_, idx, value.c_str(), static_cast<int>(value.size()),
                          SQLITE_TRANSIENT);
    }
    void integer(int idx, int value) { sqlite3_bind_int(stmt_, idx, value); }

private:
    sqlite3_stmt* stmt_{nullptr};
    bool ok_{false};
};

void set_error(std::string* error, const std::string& msg) {
    if (error != nullptr) {
        *error = msg;
    }
}

bool exec_sql(sqlite3* db, const char* sql, std::string* error) {
    char* errmsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        set_error(error, errmsg != nullptr ? errmsg : "sqlite error");
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}

HostStatus status_from(const std::string& text) {
    if (text == "up") {
        return HostStatus::Up;
    }
    if (text == "down") {
        return HostStatus::Down;
    }
    return HostStatus::Unknown;
}

RiskLevel risk_from(const std::string& text) {
    if (text == "safe") {
        return RiskLevel::Safe;
    }
    if (text == "warning") {
        return RiskLevel::Warning;
    }
    if (text == "critical") {
        return RiskLevel::Critical;
    }
    if (text == "offline") {
        return RiskLevel::Offline;
    }
    return RiskLevel::Unknown;
}

std::string column_text(sqlite3_stmt* stmt, int idx) {
    const unsigned char* raw = sqlite3_column_text(stmt, idx);
    return raw != nullptr ? reinterpret_cast<const char*>(raw) : std::string{};
}

} // namespace

Storage::Storage(std::string path) : path_(std::move(path)) {}

Storage::~Storage() {
    if (db_ != nullptr) {
        sqlite3_close(db_);
    }
}

std::string Storage::default_path() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA")) {
        if (*appdata != '\0') {
            return std::string(appdata) + "\\vnm\\storage.db";
        }
    }
    if (const char* profile = std::getenv("USERPROFILE")) {
        if (*profile != '\0') {
            return std::string(profile) + "\\.vnm\\storage.db";
        }
    }
    return "storage.db";
#else
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
#endif
}

bool Storage::is_open() const noexcept { return db_ != nullptr; }

bool Storage::open(std::string* error) {
    if (db_ != nullptr) {
        return true;
    }

    const std::filesystem::path db_path(path_);
    const std::filesystem::path dir = db_path.parent_path();
    if (!dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            set_error(error, "cannot create directory " + dir.string() + ": " + ec.message());
            return false;
        }
    }

    if (sqlite3_open(path_.c_str(), &db_) != SQLITE_OK) {
        set_error(error, std::string("cannot open ") + path_ + ": " +
                             (db_ != nullptr ? sqlite3_errmsg(db_) : "?"));
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }

    if (!exec_sql(db_, "PRAGMA foreign_keys = ON;", error) ||
        !exec_sql(db_, kSchema, error)) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    return true;
}

std::int64_t Storage::save_scan(const Scan& scan, std::string* error) {
    if (!is_open() && !open(error)) {
        return 0;
    }
    if (!exec_sql(db_, "BEGIN;", error)) {
        return 0;
    }

    auto fail = [&]() -> std::int64_t {
        exec_sql(db_, "ROLLBACK;", nullptr);
        return 0;
    };

    {
        Stmt stmt(db_, "INSERT INTO scans(target, started_at, finished_at, nmap_version) "
                       "VALUES(?,?,?,?);");
        if (!stmt.ok()) {
            set_error(error, sqlite3_errmsg(db_));
            return fail();
        }
        stmt.text(1, scan.target);
        stmt.text(2, scan.started_at);
        stmt.text(3, scan.finished_at);
        stmt.text(4, scan.nmap_version);
        if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
            set_error(error, sqlite3_errmsg(db_));
            return fail();
        }
    }

    const std::int64_t scan_id = sqlite3_last_insert_rowid(db_);

    for (const auto& host : scan.hosts) {
        Stmt host_stmt(db_,
                       "INSERT INTO hosts(scan_id,address,mac,vendor,hostname,os_name,"
                       "os_confidence,status,risk,subnet) VALUES(?,?,?,?,?,?,?,?,?,?);");
        if (!host_stmt.ok()) {
            set_error(error, sqlite3_errmsg(db_));
            return fail();
        }
        host_stmt.integer(1, static_cast<int>(scan_id));
        host_stmt.text(2, host.address);
        host_stmt.text(3, host.mac);
        host_stmt.text(4, host.vendor);
        host_stmt.text(5, host.hostname);
        host_stmt.text(6, host.os_name);
        host_stmt.integer(7, host.os_confidence);
        host_stmt.text(8, to_string(host.status));
        host_stmt.text(9, to_string(host.risk));
        host_stmt.text(10, host.subnet);
        if (sqlite3_step(host_stmt.get()) != SQLITE_DONE) {
            set_error(error, sqlite3_errmsg(db_));
            return fail();
        }
        const std::int64_t host_id = sqlite3_last_insert_rowid(db_);

        for (const auto& port : host.ports) {
            Stmt port_stmt(db_,
                           "INSERT INTO ports(host_id,number,protocol,state,service,product,"
                           "version,extrainfo) VALUES(?,?,?,?,?,?,?,?);");
            if (!port_stmt.ok()) {
                set_error(error, sqlite3_errmsg(db_));
                return fail();
            }
            port_stmt.integer(1, static_cast<int>(host_id));
            port_stmt.integer(2, port.number);
            port_stmt.text(3, port.protocol);
            port_stmt.text(4, port.state);
            port_stmt.text(5, port.service);
            port_stmt.text(6, port.product);
            port_stmt.text(7, port.version);
            port_stmt.text(8, port.extrainfo);
            if (sqlite3_step(port_stmt.get()) != SQLITE_DONE) {
                set_error(error, sqlite3_errmsg(db_));
                return fail();
            }
        }
    }

    if (!exec_sql(db_, "COMMIT;", error)) {
        return fail();
    }
    return scan_id;
}

std::vector<ScanSummary> Storage::list_scans(std::string* error) const {
    std::vector<ScanSummary> result;
    if (db_ == nullptr) {
        set_error(error, "database is not open");
        return result;
    }

    Stmt stmt(db_,
              "SELECT s.id, s.target, s.started_at, s.finished_at, s.nmap_version, "
              "s.created_at, COUNT(h.id) "
              "FROM scans s LEFT JOIN hosts h ON h.scan_id = s.id "
              "GROUP BY s.id ORDER BY s.id DESC;");
    if (!stmt.ok()) {
        set_error(error, sqlite3_errmsg(db_));
        return result;
    }

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ScanSummary summary;
        summary.id = sqlite3_column_int64(stmt.get(), 0);
        summary.target = column_text(stmt.get(), 1);
        summary.started_at = column_text(stmt.get(), 2);
        summary.finished_at = column_text(stmt.get(), 3);
        summary.nmap_version = column_text(stmt.get(), 4);
        summary.created_at = column_text(stmt.get(), 5);
        summary.host_count = static_cast<std::size_t>(sqlite3_column_int64(stmt.get(), 6));
        result.push_back(std::move(summary));
    }
    return result;
}

std::optional<Scan> Storage::load_scan(std::int64_t id, std::string* error) const {
    if (db_ == nullptr) {
        set_error(error, "database is not open");
        return std::nullopt;
    }

    Scan scan;
    {
        Stmt stmt(db_, "SELECT target, started_at, finished_at, nmap_version FROM scans "
                       "WHERE id = ?;");
        if (!stmt.ok()) {
            set_error(error, sqlite3_errmsg(db_));
            return std::nullopt;
        }
        stmt.integer(1, static_cast<int>(id));
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
            set_error(error, "scan id not found: " + std::to_string(id));
            return std::nullopt;
        }
        scan.id = id;
        scan.target = column_text(stmt.get(), 0);
        scan.started_at = column_text(stmt.get(), 1);
        scan.finished_at = column_text(stmt.get(), 2);
        scan.nmap_version = column_text(stmt.get(), 3);
    }

    std::vector<std::pair<std::int64_t, std::size_t>> host_rows;
    {
        Stmt stmt(db_,
                  "SELECT id, address, mac, vendor, hostname, os_name, os_confidence, "
                  "status, risk, subnet FROM hosts WHERE scan_id = ? ORDER BY address;");
        if (!stmt.ok()) {
            set_error(error, sqlite3_errmsg(db_));
            return std::nullopt;
        }
        stmt.integer(1, static_cast<int>(id));
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            Host host;
            const std::int64_t host_id = sqlite3_column_int64(stmt.get(), 0);
            host.address = column_text(stmt.get(), 1);
            host.mac = column_text(stmt.get(), 2);
            host.vendor = column_text(stmt.get(), 3);
            host.hostname = column_text(stmt.get(), 4);
            host.os_name = column_text(stmt.get(), 5);
            host.os_confidence = sqlite3_column_int(stmt.get(), 6);
            host.status = status_from(column_text(stmt.get(), 7));
            host.risk = risk_from(column_text(stmt.get(), 8));
            host.subnet = column_text(stmt.get(), 9);
            host_rows.emplace_back(host_id, scan.hosts.size());
            scan.hosts.push_back(std::move(host));
        }
    }

    for (const auto& [host_id, index] : host_rows) {
        Stmt stmt(db_,
                  "SELECT number, protocol, state, service, product, version, extrainfo "
                  "FROM ports WHERE host_id = ? ORDER BY number;");
        if (!stmt.ok()) {
            set_error(error, sqlite3_errmsg(db_));
            return std::nullopt;
        }
        stmt.integer(1, static_cast<int>(host_id));
        while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            Port port;
            port.number = static_cast<std::uint16_t>(sqlite3_column_int(stmt.get(), 0));
            port.protocol = column_text(stmt.get(), 1);
            port.state = column_text(stmt.get(), 2);
            port.service = column_text(stmt.get(), 3);
            port.product = column_text(stmt.get(), 4);
            port.version = column_text(stmt.get(), 5);
            port.extrainfo = column_text(stmt.get(), 6);
            scan.hosts[index].ports.push_back(std::move(port));
        }
    }

    return scan;
}

bool Storage::delete_scan(std::int64_t id, std::string* error) {
    if (!is_open() && !open(error)) {
        return false;
    }
    Stmt stmt(db_, "DELETE FROM scans WHERE id = ?;");
    if (!stmt.ok()) {
        set_error(error, sqlite3_errmsg(db_));
        return false;
    }
    stmt.integer(1, static_cast<int>(id));
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        set_error(error, sqlite3_errmsg(db_));
        return false;
    }
    return sqlite3_changes(db_) > 0;
}

std::optional<ScanDiff> Storage::diff(std::int64_t before_id, std::int64_t after_id,
                                      std::string* error) const {
    const auto before = load_scan(before_id, error);
    if (!before.has_value()) {
        return std::nullopt;
    }
    const auto after = load_scan(after_id, error);
    if (!after.has_value()) {
        return std::nullopt;
    }
    return diff_scans(*before, *after);
}

} // namespace vnm
