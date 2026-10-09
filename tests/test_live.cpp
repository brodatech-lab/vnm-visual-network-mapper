#include "test_util.hpp"

#include <string>
#include <vector>

#include "vnm/live.hpp"

int main() {
    using namespace vnm;

    // Simulated nmap normal (streamed) output.
    const std::vector<std::string> lines = {
        "Starting Nmap 7.94 ( https://nmap.org ) at 2026-01-01 00:00 UTC",
        "Initiating Ping Scan at 00:00",
        "Nmap scan report for 10.0.0.1",
        "Host is up (0.0010s latency).",
        "MAC Address: AA:BB:CC:DD:EE:FF (Acme Corp)",
        "Discovered open port 22/tcp on 10.0.0.1",
        "22/tcp   open  ssh     OpenSSH 9.0",
        "Nmap scan report for 10.0.0.2 [host down]",
        "Nmap scan report for web.lan (10.0.0.3)",
        "Host is up (0.00040s latency).",
        "80/tcp   open  http    nginx 1.24",
        "Nmap scan report for 10.0.0.4 [host down]",
    };

    LiveOutputParser parser;
    for (const auto& line : lines) {
        parser.feed_line(line);
    }
    const Scan& scan = parser.scan();

    // Down hosts must be ignored (this was the bug that flooded the map).
    CHECK(scan.host_count() == 2);
    CHECK(scan.hosts[0].address == "10.0.0.1");
    CHECK(scan.hosts[1].address == "10.0.0.3");

    CHECK(scan.hosts[0].status == HostStatus::Up);
    CHECK(scan.hosts[0].mac == "AA:BB:CC:DD:EE:FF");
    CHECK(scan.hosts[0].vendor == "Acme Corp");
    CHECK(scan.hosts[0].subnet == "10.0.0.0/24");
    CHECK(scan.hosts[0].open_port_count() == 1);
    CHECK(scan.hosts[0].ports[0].number == 22);
    CHECK(scan.hosts[0].ports[0].service == "ssh");

    CHECK(scan.hosts[1].open_port_count() == 1);
    CHECK(scan.hosts[1].ports[0].number == 80);
    CHECK(scan.hosts[1].ports[0].service == "http");

    // "Discovered open port" creates the host even without a report line.
    LiveOutputParser parser2;
    parser2.feed_line("Discovered open port 443/tcp on 192.168.5.5");
    CHECK(parser2.scan().host_count() == 1);
    CHECK(parser2.scan().hosts[0].address == "192.168.5.5");
    CHECK(parser2.scan().hosts[0].ports[0].number == 443);

    // reset()
    parser.reset();
    CHECK(parser.scan().host_count() == 0);

    return vnmtest::summary("live");
}
