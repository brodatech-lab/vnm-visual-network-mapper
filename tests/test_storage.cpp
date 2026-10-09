#include "test_util.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

#include "vnm/platform.hpp"
#include "vnm/storage.hpp"

namespace {

vnm::Scan make_scan(const std::string& target) {
    vnm::Scan scan;
    scan.target = target;
    scan.started_at = "1700000000";
    scan.finished_at = "1700000010";
    scan.nmap_version = "7.94";

    vnm::Host router;
    router.address = "192.168.0.1";
    router.mac = "AA:BB:CC:DD:EE:01";
    router.vendor = "TP-Link";
    router.hostname = "router.lan";
    router.os_name = "Linux";
    router.os_confidence = 95;
    router.status = vnm::HostStatus::Up;
    router.subnet = "192.168.0.0/24";
    router.ports.push_back(vnm::Port{22, "tcp", "open", "ssh", "OpenSSH", "9.0", ""});
    router.risk = vnm::evaluate_risk(router);
    scan.hosts.push_back(router);

    vnm::Host offline;
    offline.address = "192.168.0.99";
    offline.status = vnm::HostStatus::Down;
    offline.subnet = "192.168.0.0/24";
    offline.risk = vnm::evaluate_risk(offline);
    scan.hosts.push_back(offline);

    return scan;
}

} // namespace

int main() {
    using namespace vnm;

    const std::filesystem::path db_path =
        std::filesystem::temp_directory_path() /
        ("vnm_storage_test_" + std::to_string(vnm::process_id()) + ".db");
    std::filesystem::remove(db_path);

    {
        Storage storage(db_path.string());
        std::string error;
        CHECK(storage.open(&error));
        CHECK(error.empty());
        CHECK(storage.is_open());

        const Scan first = make_scan("192.168.0.0/24");
        const std::int64_t id1 = storage.save_scan(first, &error);
        CHECK(id1 > 0);

        // second scan: router gains port 443, a new host appears
        Scan second = make_scan("192.168.0.0/24");
        second.hosts[0].ports.push_back(
            Port{443, "tcp", "open", "https", "nginx", "1.24", ""});
        Host extra;
        extra.address = "192.168.0.50";
        extra.status = HostStatus::Up;
        extra.subnet = "192.168.0.0/24";
        extra.risk = evaluate_risk(extra);
        second.hosts.push_back(extra);
        const std::int64_t id2 = storage.save_scan(second, &error);
        CHECK(id2 > id1);

        // history (newest first)
        const auto scans = storage.list_scans(&error);
        CHECK(error.empty());
        CHECK(scans.size() == 2);
        CHECK(scans[0].id == id2);
        CHECK(scans[0].host_count == 3);
        CHECK(scans[1].id == id1);
        CHECK(scans[1].host_count == 2);
        CHECK(scans[0].nmap_version == "7.94");

        // load round-trip
        const auto loaded = storage.load_scan(id1, &error);
        CHECK(loaded.has_value());
        CHECK(loaded->host_count() == 2);
        CHECK(loaded->target == "192.168.0.0/24");
        CHECK(loaded->hosts[0].address == "192.168.0.1");
        CHECK(loaded->hosts[0].status == HostStatus::Up);
        CHECK(loaded->hosts[0].risk == RiskLevel::Warning);
        CHECK(loaded->hosts[0].os_confidence == 95);
        CHECK(loaded->hosts[0].ports.size() == 1);
        CHECK(loaded->hosts[0].ports[0].service == "ssh");
        CHECK(loaded->hosts[1].status == HostStatus::Down);
        CHECK(loaded->hosts[1].risk == RiskLevel::Offline);

        // diff id1 (before) -> id2 (after)
        const auto diff = storage.diff(id1, id2, &error);
        CHECK(diff.has_value());
        CHECK(diff->added.size() == 1);
        CHECK(diff->added[0].address == "192.168.0.50");
        CHECK(diff->changed.size() == 1);
        CHECK(diff->changed[0].added_ports.size() == 1);
        CHECK(diff->unchanged == 1);

        // missing id
        std::string missing_err;
        CHECK(!storage.load_scan(9999, &missing_err).has_value());
        CHECK(!missing_err.empty());

        // delete + cascade
        CHECK(storage.delete_scan(id1, &error));
        CHECK(storage.list_scans(&error).size() == 1);
        CHECK(!storage.delete_scan(9999, &error));
    }

    std::filesystem::remove(db_path);

    return vnmtest::summary("storage");
}
