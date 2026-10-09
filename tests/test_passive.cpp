#include "test_util.hpp"

#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <vector>

#include "vnm/passive.hpp"

namespace {

void put_mac(std::vector<std::uint8_t>& v, std::initializer_list<int> bytes) {
    for (int b : bytes) {
        v.push_back(static_cast<std::uint8_t>(b));
    }
}

void put_ipv4(std::vector<std::uint8_t>& v, int a, int b, int c, int d) {
    v.push_back(static_cast<std::uint8_t>(a));
    v.push_back(static_cast<std::uint8_t>(b));
    v.push_back(static_cast<std::uint8_t>(c));
    v.push_back(static_cast<std::uint8_t>(d));
}

// Ethernet + ARP request from AA:BB:CC:DD:EE:01 (192.168.1.50) for 192.168.1.1.
std::vector<std::uint8_t> make_arp_request() {
    std::vector<std::uint8_t> f;
    put_mac(f, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff});       // dst
    put_mac(f, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01});       // src
    f.push_back(0x08);
    f.push_back(0x06);                                      // ethertype ARP
    f.push_back(0x00);
    f.push_back(0x01);                                      // htype
    f.push_back(0x08);
    f.push_back(0x00);                                      // ptype
    f.push_back(0x06);
    f.push_back(0x04);                                      // hlen/plen
    f.push_back(0x00);
    f.push_back(0x01);                                      // oper request
    put_mac(f, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01});       // sha
    put_ipv4(f, 192, 168, 1, 50);                           // spa
    put_mac(f, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});       // tha
    put_ipv4(f, 192, 168, 1, 1);                            // tpa
    return f;
}

std::vector<std::uint8_t> make_dhcp_discover() {
    std::vector<std::uint8_t> f;
    put_mac(f, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    put_mac(f, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02});
    f.push_back(0x08);
    f.push_back(0x00);                                      // ethertype IPv4

    // IPv4 header (20 bytes)
    f.push_back(0x45);
    f.push_back(0x00);
    f.push_back(0x00);
    f.push_back(0x00);                                      // total length (unused)
    f.push_back(0x00);
    f.push_back(0x00);                                      // id
    f.push_back(0x00);
    f.push_back(0x00);                                      // flags/frag
    f.push_back(0x40);                                      // ttl
    f.push_back(0x11);                                      // proto UDP
    f.push_back(0x00);
    f.push_back(0x00);                                      // checksum
    put_ipv4(f, 0, 0, 0, 0);                                // src
    put_ipv4(f, 255, 255, 255, 255);                        // dst

    // UDP header
    f.push_back(0x00);
    f.push_back(0x44);                                      // sport 68
    f.push_back(0x00);
    f.push_back(0x43);                                      // dport 67
    f.push_back(0x00);
    f.push_back(0x00);                                      // length
    f.push_back(0x00);
    f.push_back(0x00);                                      // checksum

    // BOOTP fixed part (236) + magic cookie (4)
    std::vector<std::uint8_t> bootp(240, 0);
    bootp[0] = 1;                                           // op (request)
    bootp[1] = 1;                                           // htype ethernet
    bootp[2] = 6;                                           // hlen
    bootp[28] = 0xAA;
    bootp[29] = 0xBB;
    bootp[30] = 0xCC;
    bootp[31] = 0xDD;
    bootp[32] = 0xEE;
    bootp[33] = 0x02;                                       // chaddr
    bootp[236] = 0x63;
    bootp[237] = 0x82;
    bootp[238] = 0x53;
    bootp[239] = 0x63;                                      // magic cookie
    f.insert(f.end(), bootp.begin(), bootp.end());

    // options: 53 msg-type, 12 hostname, 60 vendor, 50 requested IP, 255 end
    const std::uint8_t options[] = {
        0x35, 0x01, 0x01,
        0x0c, 0x06, 'm', 'y', 'h', 'o', 's', 't',
        0x3c, 0x04, 'M', 'S', 'F', 'T',
        0x32, 0x04, 192, 168, 1, 77,
        0xff};
    f.insert(f.end(), std::begin(options), std::end(options));
    return f;
}

} // namespace

int main() {
    using namespace vnm;

    const auto arp = make_arp_request();
    PassiveObservation obs;
    CHECK(decode_arp(arp.data(), arp.size(), obs));
    CHECK(obs.mac == "AA:BB:CC:DD:EE:01");
    CHECK(obs.ip == "192.168.1.50");
    CHECK(obs.has_ip);
    CHECK(obs.source == "arp");
    CHECK(!decode_dhcp(arp.data(), arp.size(), obs)); // not DHCP

    const auto dhcp = make_dhcp_discover();
    PassiveObservation d;
    CHECK(decode_dhcp(dhcp.data(), dhcp.size(), d));
    CHECK(d.mac == "AA:BB:CC:DD:EE:02");
    CHECK(d.hostname == "myhost");
    CHECK(d.vendor == "MSFT");
    CHECK(d.ip == "192.168.1.77"); // from option 50 (yiaddr is zero)
    CHECK(d.has_ip);
    CHECK(d.source == "dhcp");
    CHECK(!decode_arp(dhcp.data(), dhcp.size(), d));

    // Short / wrong frames must not crash and return false.
    const std::uint8_t tiny[] = {0x00, 0x01, 0x02};
    PassiveObservation t;
    CHECK(!decode_arp(tiny, sizeof(tiny), t));
    CHECK(!decode_dhcp(tiny, sizeof(tiny), t));

#if defined(VNM_HAVE_PCAP)
    CHECK(PassiveScanner::supported());
#endif

    return vnmtest::summary("passive");
}
