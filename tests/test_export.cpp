#include "test_util.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include "vnm/export.hpp"
#include "vnm/layout.hpp"
#include "vnm/platform.hpp"

namespace {

std::string slurp(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

} // namespace

int main() {
    using namespace vnm;

    Scan scan;
    scan.target = "test";
    Host host;
    host.address = "192.168.0.10";
    host.hostname = "web.lan";
    host.vendor = "Acme";
    host.status = HostStatus::Up;
    host.status_reason = "syn-ack";
    host.subnet = "192.168.0.0/24";
    host.ports.push_back(Port{443, "tcp", "open", "https", "nginx", "1.24", ""});
    host.risk = evaluate_risk(host);
    scan.hosts.push_back(host);

    const TopologyLayout layout = layout_scan(scan);

    const std::filesystem::path dir = std::filesystem::temp_directory_path();
    const std::string base =
        (dir / ("vnm_export_test_" + std::to_string(process_id()))).string();

    std::string error;
    CHECK(export_scan(scan, layout, ExportFormat::Svg, base + ".svg", &error));
    CHECK(error.empty());
    const std::string svg = slurp(base + ".svg");
    CHECK(svg.find("<svg") != std::string::npos);
    CHECK(svg.find("192.168.0.10") != std::string::npos);
    CHECK(svg.find("192.168.0.0/24") != std::string::npos);

    CHECK(export_scan(scan, layout, ExportFormat::Json, base + ".json", &error));
    const std::string json = slurp(base + ".json");
    CHECK(json.find("\"address\": \"192.168.0.10\"") != std::string::npos);
    CHECK(json.find("\"ports\"") != std::string::npos);
    CHECK(json.find("\"risk\": \"warning\"") != std::string::npos);

    // Round-trip: import the exported JSON back into a Scan.
    Scan imported;
    std::string import_error;
    CHECK(import_scan_json(json, imported, &import_error));
    CHECK(import_error.empty());
    CHECK(imported.host_count() == 1);
    CHECK(imported.hosts[0].address == "192.168.0.10");
    CHECK(imported.hosts[0].hostname == "web.lan");
    CHECK(imported.hosts[0].vendor == "Acme");
    CHECK(imported.hosts[0].status == HostStatus::Up);
    CHECK(imported.hosts[0].risk == RiskLevel::Warning);
    CHECK(imported.hosts[0].ports.size() == 1);
    CHECK(imported.hosts[0].ports[0].number == 443);
    CHECK(imported.hosts[0].ports[0].service == "https");

    const Scan bad = [] {
        Scan s;
        std::string e;
        (void)import_scan_json("not json", s, &e);
        return s;
    }();
    CHECK(bad.host_count() == 0);

    CHECK(export_scan(scan, layout, ExportFormat::Png, base + ".png", &error));
    std::ifstream png(base + ".png", std::ios::binary);
    std::array<unsigned char, 8> signature{};
    png.read(reinterpret_cast<char*>(signature.data()), signature.size());
    const std::array<unsigned char, 8> expected{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
    CHECK(signature == expected);

    std::error_code ec;
    std::filesystem::remove(base + ".svg", ec);
    std::filesystem::remove(base + ".json", ec);
    std::filesystem::remove(base + ".png", ec);

    bool ok = true;
    CHECK(parse_format("png", &ok) == ExportFormat::Png);
    CHECK(ok);
    (void)parse_format("bogus", &ok);
    CHECK(!ok);

    return vnmtest::summary("export");
}
