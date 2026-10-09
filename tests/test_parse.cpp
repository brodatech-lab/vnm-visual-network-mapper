#include "test_util.hpp"

#include <string>

#include "vnm/parse.hpp"

namespace {

const char* kSample = R"XML(<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.0/24" start="1700000000"
         version="7.94">
  <hosthint>
    <status state="up" reason="unknown-response"/>
    <address addr="192.168.1.77" addrtype="ipv4"/>
  </hosthint>
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TP-Link"/>
    <hostnames><hostname name="router.lan" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.4 - 5.15" accuracy="96"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
        <script id="vulners" output="[CVE-2021-41617] OpenSSH 8.9p1 / 8.9p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
    <hostscript>
      <script id="vuln" output="VULNERABLE: CVE-2020-1234"/>
    </hostscript>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.250" addrtype="ipv4"/>
    <ports/>
  </host>
  <runstats>
    <finished time="1700000012" elapsed="12" summary="done"/>
  </runstats>
</nmaprun>)XML";

} // namespace

int main() {
    using namespace vnm;

    const Scan scan = NmapXmlParser::parse(kSample);

    CHECK(scan.nmap_version == "7.94");
    CHECK(scan.finished_at == "1700000012");
    CHECK(scan.host_count() == 2);

    const Host& router = scan.hosts[0];
    CHECK(router.address == "192.168.1.1");
    CHECK(router.mac == "AA:BB:CC:DD:EE:FF");
    CHECK(router.vendor == "TP-Link");
    CHECK(router.hostname == "router.lan");
    CHECK(router.os_name == "Linux 5.4 - 5.15");
    CHECK(router.os_confidence == 96);
    CHECK(router.status == HostStatus::Up);
    CHECK(router.subnet == "192.168.1.0/24");
    CHECK(router.ports.size() == 3);
    CHECK(router.open_port_count() == 2);
    CHECK(router.ports[0].service == "ssh");
    CHECK(router.ports[0].product == "OpenSSH");
    CHECK(router.ports[0].version == "8.9p1");
    CHECK(router.ports[2].state == "closed");
    CHECK(router.risk == RiskLevel::Critical); // telnet exposed

    // NSE scripts and CVE extraction (port + host level).
    CHECK(router.ports[0].cves.size() == 1);
    CHECK(router.ports[0].cves[0] == "CVE-2021-41617");
    CHECK(router.ports[0].scripts.size() == 1);
    CHECK(router.ports[0].scripts[0].id == "vulners");
    CHECK(router.cves.size() == 1);
    CHECK(router.cves[0] == "CVE-2020-1234");

    const Host& offline = scan.hosts[1];
    CHECK(offline.status == HostStatus::Down);
    CHECK(offline.risk == RiskLevel::Offline);

    // Malformed input must not crash and must yield an empty scan.
    const Scan bad = NmapXmlParser::parse("not xml at all");
    CHECK(bad.host_count() == 0);
    CHECK(bad.nmap_version.empty());

    return vnmtest::summary("parse");
}
