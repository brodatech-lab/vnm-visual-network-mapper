#include "vnm/export.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace vnm::stbwrap {
int png_write(const char* path, int width, int height, int components,
              const unsigned char* data, int stride);
int font_print(float x, float y, const char* text, const unsigned char color[4],
               void* buffer, int buffer_size);
} // namespace vnm::stbwrap

namespace vnm {
namespace {

std::uint32_t risk_rgb(RiskLevel level) { return risk_color(level); }

std::string hex(std::uint32_t rgb) {
    static const char* digits = "0123456789abcdef";
    std::string out = "#";
    out.push_back(digits[(rgb >> 20) & 0xF]);
    out.push_back(digits[(rgb >> 16) & 0xF]);
    out.push_back(digits[(rgb >> 12) & 0xF]);
    out.push_back(digits[(rgb >> 8) & 0xF]);
    out.push_back(digits[(rgb >> 4) & 0xF]);
    out.push_back(digits[rgb & 0xF]);
    return out;
}

std::string xml_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string json_escape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 2);
    for (const char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

struct Geometry {
    const TopologyLayout* layout;
    const LayoutConfig* config;
    float width;
    float height;
    float padding;
};

std::string subtitle_of(const Host& host) {
    if (!host.hostname.empty()) {
        return host.hostname;
    }
    if (!host.vendor.empty()) {
        return host.vendor;
    }
    return "open:" + std::to_string(host.open_port_count());
}

bool ends_with_dot_one(const std::string& address) {
    return address.size() >= 2 && address.compare(address.size() - 2, 2, ".1") == 0;
}

// ------------------------------------------------------------------- SVG

void svg_write(std::ostream& out, const Scan& scan, const Geometry& geo) {
    const TopologyLayout& layout = *geo.layout;
    const LayoutConfig& cfg = *geo.config;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << geo.width
        << "\" height=\"" << geo.height << "\" viewBox=\"0 0 " << geo.width << ' '
        << geo.height << "\" font-family=\"monospace\">\n";
    out << "  <rect width=\"100%\" height=\"100%\" fill=\"#181a1f\"/>\n";

    // legend
    const struct {
        const char* label;
        RiskLevel level;
    } legend[] = {{"safe", RiskLevel::Safe},
                  {"warning", RiskLevel::Warning},
                  {"critical", RiskLevel::Critical},
                  {"offline", RiskLevel::Offline}};
    float lx = 16.0f;
    for (const auto& item : legend) {
        out << "  <rect x=\"" << lx << "\" y=\"16\" width=\"12\" height=\"12\" fill=\""
            << hex(risk_rgb(item.level)) << "\"/>\n";
        out << "  <text x=\"" << (lx + 18.0f) << "\" y=\"27\" fill=\"#aab2bd\" "
            << "font-size=\"13\">" << xml_escape(item.label) << "</text>\n";
        lx += 100.0f;
    }

    const float ox = geo.padding;
    const float oy = geo.padding;

    // subnet frames
    for (const auto& cluster : layout.clusters) {
        out << "  <rect x=\"" << (ox + cluster.x) << "\" y=\"" << (oy + cluster.y)
            << "\" width=\"" << cluster.width << "\" height=\"" << cluster.height
            << "\" rx=\"8\" fill=\"#21252d\" stroke=\"#485262\" stroke-width=\"2\"/>\n";
        out << "  <text x=\"" << (ox + cluster.x + 10.0f) << "\" y=\""
            << (oy + cluster.y + 20.0f) << "\" fill=\"#96a0af\" font-size=\"13\">"
            << xml_escape(cluster.cidr) << "</text>\n";
    }

    // host index -> node position
    std::vector<const NodePosition*> pos(scan.hosts.size(), nullptr);
    for (const auto& node : layout.nodes) {
        if (node.host_index < pos.size()) {
            pos[node.host_index] = &node;
        }
    }

    // gateway edges
    for (const auto& cluster : layout.clusters) {
        const NodePosition* hub = nullptr;
        for (const std::size_t hi : cluster.hosts) {
            if (hi < scan.hosts.size() && ends_with_dot_one(scan.hosts[hi].address)) {
                hub = pos[hi];
                break;
            }
        }
        if (hub == nullptr) {
            continue;
        }
        const float hx = ox + hub->x + cfg.node_width * 0.5f;
        const float hy = oy + hub->y + cfg.node_height * 0.5f;
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = pos[hi];
            if (node == nullptr || node == hub) {
                continue;
            }
            out << "  <line x1=\"" << hx << "\" y1=\"" << hy << "\" x2=\""
                << (ox + node->x + cfg.node_width * 0.5f) << "\" y2=\""
                << (oy + node->y + cfg.node_height * 0.5f)
                << "\" stroke=\"#5a6472\" stroke-width=\"1.5\"/>\n";
        }
    }

    // nodes
    for (const auto& node : layout.nodes) {
        if (node.host_index >= scan.hosts.size()) {
            continue;
        }
        const Host& host = scan.hosts[node.host_index];
        const float x = ox + node.x;
        const float y = oy + node.y;
        out << "  <rect x=\"" << x << "\" y=\"" << y << "\" width=\"" << cfg.node_width
            << "\" height=\"" << cfg.node_height << "\" rx=\"6\" fill=\"#282c34\" "
            << "stroke=\"" << hex(risk_rgb(host.risk)) << "\" stroke-width=\"2\"/>\n";
        out << "  <text x=\"" << (x + 10.0f) << "\" y=\"" << (y + 20.0f)
            << "\" fill=\"#ecf0f3\" font-size=\"14\">" << xml_escape(host.address)
            << "</text>\n";
        out << "  <text x=\"" << (x + 10.0f) << "\" y=\"" << (y + 38.0f)
            << "\" fill=\"#9aa3b0\" font-size=\"12\">"
            << xml_escape(subtitle_of(host)) << "</text>\n";
    }

    out << "</svg>\n";
}

// ------------------------------------------------------------------- JSON

void json_write(std::ostream& out, const Scan& scan, const Geometry& geo) {
    const TopologyLayout& layout = *geo.layout;
    std::vector<const NodePosition*> pos(scan.hosts.size(), nullptr);
    for (const auto& node : layout.nodes) {
        if (node.host_index < pos.size()) {
            pos[node.host_index] = &node;
        }
    }

    out << "{\n";
    out << "  \"target\": \"" << json_escape(scan.target) << "\",\n";
    out << "  \"nmap_version\": \"" << json_escape(scan.nmap_version) << "\",\n";
    out << "  \"started_at\": \"" << json_escape(scan.started_at) << "\",\n";
    out << "  \"finished_at\": \"" << json_escape(scan.finished_at) << "\",\n";
    out << "  \"hosts\": [\n";
    for (std::size_t i = 0; i < scan.hosts.size(); ++i) {
        const Host& host = scan.hosts[i];
        out << "    {\n";
        out << "      \"address\": \"" << json_escape(host.address) << "\",\n";
        out << "      \"mac\": \"" << json_escape(host.mac) << "\",\n";
        out << "      \"vendor\": \"" << json_escape(host.vendor) << "\",\n";
        out << "      \"hostname\": \"" << json_escape(host.hostname) << "\",\n";
        out << "      \"os\": \"" << json_escape(host.os_name) << "\",\n";
        out << "      \"os_confidence\": " << host.os_confidence << ",\n";
        out << "      \"status\": \"" << to_string(host.status) << "\",\n";
        out << "      \"risk\": \"" << to_string(host.risk) << "\",\n";
        out << "      \"subnet\": \"" << json_escape(host.subnet) << "\",\n";
        if (pos[i] != nullptr) {
            out << "      \"x\": " << pos[i]->x << ", \"y\": " << pos[i]->y << ",\n";
        }
        out << "      \"ports\": [";
        for (std::size_t p = 0; p < host.ports.size(); ++p) {
            const Port& port = host.ports[p];
            if (p != 0) {
                out << ", ";
            }
            out << "{\"number\": " << port.number << ", \"protocol\": \""
                << json_escape(port.protocol) << "\", \"state\": \""
                << json_escape(port.state) << "\", \"service\": \""
                << json_escape(port.service) << "\", \"product\": \""
                << json_escape(port.product) << "\", \"version\": \""
                << json_escape(port.version) << "\"}";
        }
        out << "]\n";
        out << "    }" << (i + 1 < scan.hosts.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

// -------------------------------------------------------------------- PNG

struct Raster {
    int width;
    int height;
    std::vector<std::uint8_t> pixels; // RGBA

    Raster(int w, int h) : width(w), height(h), pixels(static_cast<std::size_t>(w) * h * 4, 0) {}

    void blend(int x, int y, std::uint32_t rgb, std::uint8_t a) {
        if (x < 0 || y < 0 || x >= width || y >= height || a == 0) {
            return;
        }
        std::uint8_t* p = &pixels[(static_cast<std::size_t>(y) * width + x) * 4];
        const int r = static_cast<int>((rgb >> 16) & 0xFF);
        const int g = static_cast<int>((rgb >> 8) & 0xFF);
        const int b = static_cast<int>(rgb & 0xFF);
        p[0] = static_cast<std::uint8_t>((r * a + p[0] * (255 - a)) / 255);
        p[1] = static_cast<std::uint8_t>((g * a + p[1] * (255 - a)) / 255);
        p[2] = static_cast<std::uint8_t>((b * a + p[2] * (255 - a)) / 255);
        p[3] = 255;
    }

    void fill_rect(float x0, float y0, float x1, float y1, std::uint32_t rgb) {
        const int ix0 = std::max(0, static_cast<int>(x0));
        const int iy0 = std::max(0, static_cast<int>(y0));
        const int ix1 = std::min(width - 1, static_cast<int>(x1 + 0.5f));
        const int iy1 = std::min(height - 1, static_cast<int>(y1 + 0.5f));
        for (int y = iy0; y <= iy1; ++y) {
            for (int x = ix0; x <= ix1; ++x) {
                blend(x, y, rgb, 255);
            }
        }
    }

    void stroke_rect(float x0, float y0, float x1, float y1, std::uint32_t rgb,
                     float thickness) {
        fill_rect(x0, y0, x1, y0 + thickness, rgb);
        fill_rect(x0, y1 - thickness, x1, y1, rgb);
        fill_rect(x0, y0, x0 + thickness, y1, rgb);
        fill_rect(x1 - thickness, y0, x1, y1, rgb);
    }

    void line(float x0, float y0, float x1, float y1, std::uint32_t rgb,
              float thickness) {
        const float dx = x1 - x0;
        const float dy = y1 - y0;
        const float steps = std::max(std::abs(dx), std::abs(dy));
        if (steps <= 0.0f) {
            return;
        }
        for (float t = 0.0f; t <= steps; t += 1.0f) {
            const float x = x0 + dx * (t / steps);
            const float y = y0 + dy * (t / steps);
            fill_rect(x, y, x + thickness - 1.0f, y + thickness - 1.0f, rgb);
        }
    }

    void text(float x, float y, const std::string& str, std::uint32_t rgb,
              float scale) {
        static std::vector<char> buffer(1024 * 64);
        const unsigned char color[4] = {static_cast<unsigned char>((rgb >> 16) & 0xFF),
                                        static_cast<unsigned char>((rgb >> 8) & 0xFF),
                                        static_cast<unsigned char>(rgb & 0xFF), 255};
        const int used = stbwrap::font_print(0.0f, 0.0f, str.c_str(), color,
                                             buffer.data(),
                                             static_cast<int>(buffer.size()));
        const int quads = used / 64;
        for (int q = 0; q < quads; ++q) {
            const char* v = buffer.data() + q * 64;
            float minx = 1e9f;
            float miny = 1e9f;
            float maxx = -1e9f;
            float maxy = -1e9f;
            for (int vertex = 0; vertex < 4; ++vertex) {
                float vx = 0.0f;
                float vy = 0.0f;
                std::memcpy(&vx, v + vertex * 16, sizeof(float));
                std::memcpy(&vy, v + vertex * 16 + 4, sizeof(float));
                minx = std::min(minx, vx);
                miny = std::min(miny, vy);
                maxx = std::max(maxx, vx);
                maxy = std::max(maxy, vy);
            }
            fill_rect(x + minx * scale, y + miny * scale, x + maxx * scale,
                      y + maxy * scale, rgb);
        }
    }
};

bool png_write(const std::string& path, const Scan& scan, const Geometry& geo,
               std::string* error) {
    const TopologyLayout& layout = *geo.layout;
    const LayoutConfig& cfg = *geo.config;
    const int w = static_cast<int>(geo.width);
    const int h = static_cast<int>(geo.height);
    Raster raster(w, h);
    raster.fill_rect(0, 0, static_cast<float>(w), static_cast<float>(h), 0x181A1F);

    const float ox = geo.padding;
    const float oy = geo.padding;

    // legend
    float lx = 16.0f;
    const struct {
        const char* label;
        RiskLevel level;
    } legend[] = {{"safe", RiskLevel::Safe},
                  {"warning", RiskLevel::Warning},
                  {"critical", RiskLevel::Critical},
                  {"offline", RiskLevel::Offline}};
    for (const auto& item : legend) {
        raster.fill_rect(lx, 14.0f, lx + 12.0f, 26.0f, risk_rgb(item.level));
        raster.text(lx + 18.0f, 16.0f, item.label, 0xAAB2BD, 1.0f);
        lx += 100.0f;
    }

    for (const auto& cluster : layout.clusters) {
        raster.fill_rect(ox + cluster.x, oy + cluster.y, ox + cluster.x + cluster.width,
                         oy + cluster.y + cluster.height, 0x21252D);
        raster.stroke_rect(ox + cluster.x, oy + cluster.y, ox + cluster.x + cluster.width,
                           oy + cluster.y + cluster.height, 0x485262, 2.0f);
        raster.text(ox + cluster.x + 10.0f, oy + cluster.y + 8.0f, cluster.cidr,
                    0x96A0AF, 1.0f);
    }

    std::vector<const NodePosition*> pos(scan.hosts.size(), nullptr);
    for (const auto& node : layout.nodes) {
        if (node.host_index < pos.size()) {
            pos[node.host_index] = &node;
        }
    }

    for (const auto& cluster : layout.clusters) {
        const NodePosition* hub = nullptr;
        for (const std::size_t hi : cluster.hosts) {
            if (hi < scan.hosts.size() && ends_with_dot_one(scan.hosts[hi].address)) {
                hub = pos[hi];
                break;
            }
        }
        if (hub == nullptr) {
            continue;
        }
        const float hx = ox + hub->x + cfg.node_width * 0.5f;
        const float hy = oy + hub->y + cfg.node_height * 0.5f;
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = pos[hi];
            if (node == nullptr || node == hub) {
                continue;
            }
            raster.line(hx, hy, ox + node->x + cfg.node_width * 0.5f,
                        oy + node->y + cfg.node_height * 0.5f, 0x5A6472, 1.0f);
        }
    }

    for (const auto& node : layout.nodes) {
        if (node.host_index >= scan.hosts.size()) {
            continue;
        }
        const Host& host = scan.hosts[node.host_index];
        const float x = ox + node.x;
        const float y = oy + node.y;
        raster.fill_rect(x, y, x + cfg.node_width, y + cfg.node_height, 0x282C34);
        raster.stroke_rect(x, y, x + cfg.node_width, y + cfg.node_height,
                           risk_rgb(host.risk), 2.0f);
        raster.text(x + 10.0f, y + 8.0f, host.address, 0xECF0F3, 1.0f);
        raster.text(x + 10.0f, y + 26.0f, subtitle_of(host), 0x9AA3B0, 1.0f);
    }

    if (stbwrap::png_write(path.c_str(), w, h, 4, raster.pixels.data(), w * 4) == 0) {
        if (error != nullptr) {
            *error = "failed to write PNG: " + path;
        }
        return false;
    }
    return true;
}

} // namespace

const char* to_string(ExportFormat format) noexcept {
    switch (format) {
        case ExportFormat::Svg: return "svg";
        case ExportFormat::Png: return "png";
        case ExportFormat::Json: return "json";
    }
    return "svg";
}

ExportFormat parse_format(const std::string& text, bool* ok) {
    if (ok != nullptr) {
        *ok = true;
    }
    if (text == "png") {
        return ExportFormat::Png;
    }
    if (text == "json") {
        return ExportFormat::Json;
    }
    if (text == "svg") {
        return ExportFormat::Svg;
    }
    if (ok != nullptr) {
        *ok = false;
    }
    return ExportFormat::Svg;
}

bool export_scan(const Scan& scan, const TopologyLayout& layout, ExportFormat format,
                 const std::string& path, std::string* error) {
    const LayoutConfig config;
    Geometry geo;
    geo.layout = &layout;
    geo.config = &config;
    geo.padding = 48.0f;
    geo.width = layout.width + geo.padding * 2.0f;
    geo.height = layout.height + geo.padding * 2.0f + 24.0f;
    if (geo.width < 320.0f) {
        geo.width = 320.0f;
    }
    if (geo.height < 200.0f) {
        geo.height = 200.0f;
    }

    if (format == ExportFormat::Png) {
        return png_write(path, scan, geo, error);
    }

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        if (error != nullptr) {
            *error = "cannot write " + path;
        }
        return false;
    }
    if (format == ExportFormat::Json) {
        json_write(out, scan, geo);
    } else {
        svg_write(out, scan, geo);
    }
    if (!out) {
        if (error != nullptr) {
            *error = "failed writing " + path;
        }
        return false;
    }
    return true;
}

} // namespace vnm
