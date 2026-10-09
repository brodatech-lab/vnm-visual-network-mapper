#include "test_util.hpp"

#include <string>

#include "vnm/diff.hpp"
#include "vnm/model.hpp"

namespace {

vnm::Host make_host(const std::string& address, vnm::HostStatus status,
                    std::vector<vnm::Port> ports) {
    vnm::Host host;
    host.address = address;
    host.status = status;
    host.ports = std::move(ports);
    host.risk = vnm::evaluate_risk(host);
    return host;
}

} // namespace

int main() {
    using namespace vnm;

    Scan before;
    before.hosts.push_back(make_host("10.0.0.1", HostStatus::Up,
                                     {Port{22, "tcp", "open", "ssh", "OpenSSH", "9.0", ""}}));
    before.hosts.push_back(make_host("10.0.0.2", HostStatus::Up,
                                     {Port{80, "tcp", "open", "http", "nginx", "1.24", ""}}));

    Scan after;
    after.hosts.push_back(make_host("10.0.0.1", HostStatus::Up,
                                    {Port{22, "tcp", "open", "ssh", "OpenSSH", "9.0", ""},
                                     Port{443, "tcp", "open", "https", "nginx", "1.24", ""}}));
    after.hosts.push_back(make_host("10.0.0.3", HostStatus::Up, {}));

    const ScanDiff diff = diff_scans(before, after);
    CHECK(diff.total_before == 2);
    CHECK(diff.total_after == 2);
    CHECK(diff.added.size() == 1);
    CHECK(diff.added[0].address == "10.0.0.3");
    CHECK(diff.removed.size() == 1);
    CHECK(diff.removed[0].address == "10.0.0.2");
    CHECK(diff.changed.size() == 1);
    CHECK(diff.changed[0].after.address == "10.0.0.1");
    CHECK(diff.changed[0].added_ports.size() == 1);
    CHECK(diff.changed[0].added_ports[0].number == 443);
    CHECK(diff.changed[0].removed_ports.empty());
    CHECK(diff.changed[0].modified_ports.empty());
    CHECK(!diff.changed[0].status_changed);
    CHECK(diff.unchanged == 0);
    CHECK(!diff.empty());

    // Identical scans -> no changes.
    const ScanDiff same = diff_scans(before, before);
    CHECK(same.empty());
    CHECK(same.unchanged == 2);

    // Status change + modified port details.
    Scan down;
    down.hosts.push_back(make_host("10.0.0.1", HostStatus::Down,
                                   {Port{22, "tcp", "closed", "ssh", "OpenSSH", "9.1", ""}}));
    const ScanDiff status_diff = diff_scans(before, down);
    CHECK(status_diff.changed.size() == 1);
    CHECK(status_diff.changed[0].status_changed);
    CHECK(status_diff.changed[0].modified_ports.size() == 1);
    CHECK(status_diff.changed[0].modified_ports[0].before.state == "open");
    CHECK(status_diff.changed[0].modified_ports[0].after.state == "closed");

    CHECK(same_host_state(before.hosts[0], after.hosts[0]) == false);

    return vnmtest::summary("diff");
}
