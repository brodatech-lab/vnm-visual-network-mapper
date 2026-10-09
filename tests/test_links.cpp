#include "test_util.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "vnm/links.hpp"

namespace {

bool has_url_containing(const std::vector<vnm::RefLink>& links, const std::string& needle) {
    return std::any_of(links.begin(), links.end(), [&](const vnm::RefLink& l) {
        return l.url.find(needle) != std::string::npos;
    });
}

} // namespace

int main() {
    using namespace vnm;

    // CVE extraction: unique, case-insensitive, needs 4-digit year + 4+ digits.
    const std::vector<std::string> cves = extract_cves(
        "vulns: cve-2021-41617 and CVE-2022-1234, again CVE-2021-41617; bogus CVE-21-1");
    CHECK(cves.size() == 2);
    CHECK(cves[0] == "CVE-2021-41617");
    CHECK(cves[1] == "CVE-2022-1234");

    CHECK(url_encode("OpenSSH 8.9p1") == "OpenSSH%208.9p1");
    CHECK(url_encode("a/b?c") == "a%2Fb%3Fc");

    Host host;
    host.address = "10.0.0.5";
    Port port;
    port.number = 22;
    port.protocol = "tcp";
    port.state = "open";
    port.service = "ssh";
    port.product = "OpenSSH";
    port.version = "8.9p1";
    port.cves.push_back("CVE-2021-41617");
    host.ports.push_back(port);

    const std::vector<RefLink> links = port_links(host, port);
    // 3 info + 3 service + 1 CVE
    CHECK(links.size() == 7);
    CHECK(has_url_containing(links, "speedguide.net/port.php?port=22"));
    CHECK(has_url_containing(links, "iana.org"));
    CHECK(has_url_containing(links, "shodan.io/search"));
    CHECK(has_url_containing(links, "vulners.com/search"));
    CHECK(has_url_containing(links, "nvd.nist.gov/vuln/search"));
    CHECK(has_url_containing(links, "exploit-db.com/search"));
    CHECK(has_url_containing(links, "nvd.nist.gov/vuln/detail/CVE-2021-41617"));

    // A port with no service info only yields the three info links.
    Port bare;
    bare.number = 80;
    const std::vector<RefLink> bare_links = port_links(host, bare);
    CHECK(bare_links.size() == 3);

    host.cves.push_back("CVE-2020-9999");
    const std::vector<RefLink> hlinks = host_links(host);
    CHECK(hlinks.size() == 1);
    CHECK(has_url_containing(hlinks, "CVE-2020-9999"));

    return vnmtest::summary("links");
}
