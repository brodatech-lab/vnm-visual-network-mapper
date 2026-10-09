#include "test_util.hpp"

#include <cstdio>
#include <fstream>
#include <string>

#include "vnm/net.hpp"

namespace {
constexpr const char* kRouteFixture = "vnm_test_route_fixture.txt";
}

int main() {
    using namespace vnm;

    CHECK(NetInfo::prefix_length("255.255.255.0") == 24);
    CHECK(NetInfo::prefix_length("255.255.0.0") == 16);
    CHECK(NetInfo::prefix_length("0.0.0.0") == 0);
    CHECK(NetInfo::prefix_length("255.255.255.255") == 32);
    CHECK(NetInfo::prefix_length("garbage") == 0);

    CHECK(NetInfo::cidr_for("192.168.1.10", "255.255.255.0") == "192.168.1.10/24");
    CHECK(NetInfo::cidr_for("", "255.255.255.0").empty());

    {
        std::ofstream out(kRouteFixture);
        out << "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        out << "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        out << "eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    }

    const auto routes = NetInfo::routes(kRouteFixture);
    CHECK(routes.size() == 2);
    CHECK(routes[0].is_default);
    CHECK(routes[0].gateway == "192.168.2.1");
    CHECK(routes[0].interface_name == "eth0");
    CHECK(!routes[1].is_default);
    CHECK(routes[1].destination == "192.168.2.0");

    const auto def = NetInfo::default_route(kRouteFixture);
    CHECK(def.has_value());
    CHECK(def->gateway == "192.168.2.1");

    std::remove(kRouteFixture);
    return vnmtest::summary("net");
}
