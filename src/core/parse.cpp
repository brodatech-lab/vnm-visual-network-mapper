#include "vnm/parse.hpp"

#include <cstdlib>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vnm {
namespace {

// ---------------------------------------------------------------------------
// Minimal XML tree used only inside this translation unit.
// ---------------------------------------------------------------------------
struct XmlNode {
    std::string name;
    std::vector<std::pair<std::string, std::string>> attrs;
    std::vector<XmlNode> children;
    std::string text;

    [[nodiscard]] const std::string* attr(std::string_view key) const {
        for (const auto& [k, v] : attrs) {
            if (k == key) {
                return &v;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const XmlNode* child(std::string_view tag) const {
        for (const auto& c : children) {
            if (c.name == tag) {
                return &c;
            }
        }
        return nullptr;
    }
};

std::string decode_entities(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '&') {
            out.push_back(in[i]);
            continue;
        }
        const std::size_t semi = in.find(';', i);
        if (semi == std::string_view::npos || semi - i > 12) {
            out.push_back('&');
            continue;
        }
        const std::string_view ent = in.substr(i + 1, semi - i - 1);
        if (ent == "amp") {
            out.push_back('&');
        } else if (ent == "lt") {
            out.push_back('<');
        } else if (ent == "gt") {
            out.push_back('>');
        } else if (ent == "quot") {
            out.push_back('"');
        } else if (ent == "apos") {
            out.push_back('\'');
        } else if (!ent.empty() && ent[0] == '#') {
            const bool hex = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X');
            const std::string digits(ent.substr(hex ? 2 : 1));
            const long code = std::strtol(digits.c_str(), nullptr, hex ? 16 : 10);
            if (code > 0 && code < 0x80) {
                out.push_back(static_cast<char>(code));
            } else if (code >= 0x80 && code < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            } else if (code >= 0x800 && code < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
        } else {
            out.append(in.substr(i, semi - i + 1));
        }
        i = semi;
    }
    return out;
}

bool is_name_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':' ||
           c == '.';
}

class XmlReader {
public:
    explicit XmlReader(std::string_view xml) : xml_(xml) {}

    [[nodiscard]] std::optional<XmlNode> parse_document() {
        skip_misc();
        if (peek() != '<' || peek(1) == '/' || peek(1) == '?' || peek(1) == '!') {
            return std::nullopt;
        }
        return std::optional<XmlNode>(parse_element());
    }

private:
    std::string_view xml_;
    std::size_t pos_{0};

    [[nodiscard]] char peek(std::size_t ahead = 0) const {
        const std::size_t idx = pos_ + ahead;
        return idx < xml_.size() ? xml_[idx] : '\0';
    }
    [[nodiscard]] bool eof() const { return pos_ >= xml_.size(); }

    void skip_ws() {
        while (!eof() && (peek() == ' ' || peek() == '\t' || peek() == '\n' ||
                          peek() == '\r')) {
            ++pos_;
        }
    }

    void skip_until(const std::string_view terminator) {
        const std::size_t at = xml_.find(terminator, pos_);
        pos_ = (at == std::string_view::npos) ? xml_.size() : at + terminator.size();
    }

    void skip_misc() {
        for (;;) {
            skip_ws();
            if (peek() == '<' && peek(1) == '?') {
                skip_until("?>");
            } else if (peek() == '<' && peek(1) == '!') {
                if (xml_.substr(pos_, 4) == "<!--") {
                    skip_until("-->");
                } else {
                    skip_until(">");
                }
            } else {
                break;
            }
        }
    }

    std::string read_name() {
        const std::size_t start = pos_;
        while (!eof() && is_name_char(peek())) {
            ++pos_;
        }
        return std::string(xml_.substr(start, pos_ - start));
    }

    std::string read_quoted() {
        const char quote = peek();
        if (quote != '"' && quote != '\'') {
            return {};
        }
        ++pos_;
        const std::size_t start = pos_;
        while (!eof() && peek() != quote) {
            ++pos_;
        }
        std::string value = decode_entities(xml_.substr(start, pos_ - start));
        if (!eof()) {
            ++pos_; // closing quote
        }
        return value;
    }

    XmlNode parse_element() {
        XmlNode node;
        ++pos_; // consume '<'
        node.name = read_name();

        // attributes
        for (;;) {
            skip_ws();
            if (peek() == '/' || peek() == '>' || eof()) {
                break;
            }
            std::string key = read_name();
            skip_ws();
            if (peek() == '=') {
                ++pos_;
                skip_ws();
                node.attrs.emplace_back(std::move(key), read_quoted());
            } else if (!key.empty()) {
                node.attrs.emplace_back(std::move(key), std::string{});
            } else {
                ++pos_; // unexpected char; avoid infinite loop
            }
        }

        if (peek() == '/') {
            ++pos_; // '/'
            if (peek() == '>') {
                ++pos_;
            }
            return node; // self closing
        }
        if (peek() == '>') {
            ++pos_;
        }

        // content
        for (;;) {
            if (eof()) {
                break;
            }
            if (peek() == '<') {
                if (peek(1) == '/') {
                    ++pos_; // '/'
                    ++pos_; // consume '<'? (already consumed only '/')
                    (void)read_name();
                    while (!eof() && peek() != '>') {
                        ++pos_;
                    }
                    if (!eof()) {
                        ++pos_;
                    }
                    break;
                }
                if (peek(1) == '!') {
                    if (xml_.substr(pos_, 4) == "<!--") {
                        skip_until("-->");
                    } else {
                        skip_until(">");
                    }
                    continue;
                }
                if (peek(1) == '?') {
                    skip_until("?>");
                    continue;
                }
                node.children.push_back(parse_element());
                continue;
            }
            const std::size_t start = pos_;
            while (!eof() && peek() != '<') {
                ++pos_;
            }
            node.text += decode_entities(xml_.substr(start, pos_ - start));
        }
        return node;
    }
};

// ---------------------------------------------------------------------------
// Nmap mapping helpers
// ---------------------------------------------------------------------------
std::string ipv4_subnet(const std::string& ip, int prefix) {
    int octets[4] = {0, 0, 0, 0};
    int idx = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= ip.size() && idx < 4; ++i) {
        if (i == ip.size() || ip[i] == '.') {
            octets[idx++] = std::atoi(ip.substr(start, i - start).c_str());
            start = i + 1;
        }
    }
    if (idx != 4 || ip.find(':') != std::string::npos) {
        return {};
    }
    const unsigned host = (static_cast<unsigned>(octets[0]) << 24) |
                          (static_cast<unsigned>(octets[1]) << 16) |
                          (static_cast<unsigned>(octets[2]) << 8) |
                          static_cast<unsigned>(octets[3]);
    const unsigned mask =
        prefix == 0 ? 0u : (~0u << (32 - static_cast<unsigned>(prefix)));
    const unsigned net = host & mask;
    return std::to_string((net >> 24) & 0xFFu) + "." +
           std::to_string((net >> 16) & 0xFFu) + "." +
           std::to_string((net >> 8) & 0xFFu) + "." +
           std::to_string(net & 0xFFu) + "/" + std::to_string(prefix);
}

void parse_host(const XmlNode& node, Host& host) {
    if (const XmlNode* status = node.child("status")) {
        if (const std::string* state = status->attr("state")) {
            host.status = (*state == "up") ? HostStatus::Up : HostStatus::Down;
        }
        if (const std::string* reason = status->attr("reason")) {
            host.status_reason = *reason;
        }
    }

    for (const auto& addr : node.children) {
        if (addr.name != "address") {
            continue;
        }
        const std::string* type = addr.attr("addrtype");
        const std::string* value = addr.attr("addr");
        if (type == nullptr || value == nullptr) {
            continue;
        }
        if (*type == "ipv4" && host.address.empty()) {
            host.address = *value;
        } else if (*type == "ipv6" && host.address.empty()) {
            host.address = *value;
        } else if (*type == "mac") {
            host.mac = *value;
            if (const std::string* vendor = addr.attr("vendor")) {
                host.vendor = *vendor;
            }
        }
    }

    if (const XmlNode* hostnames = node.child("hostnames")) {
        for (const auto& hn : hostnames->children) {
            if (hn.name == "hostname") {
                if (const std::string* name = hn.attr("name")) {
                    if (!name->empty()) {
                        host.hostname = *name;
                        break;
                    }
                }
            }
        }
    }

    if (const XmlNode* os = node.child("os")) {
        for (const auto& match : os->children) {
            if (match.name != "osmatch") {
                continue;
            }
            if (const std::string* name = match.attr("name")) {
                host.os_name = *name;
            }
            if (const std::string* acc = match.attr("accuracy")) {
                host.os_confidence = std::atoi(acc->c_str());
            }
            break;
        }
    }

    if (const XmlNode* ports = node.child("ports")) {
        for (const auto& p : ports->children) {
            if (p.name != "port") {
                continue;
            }
            Port port;
            if (const std::string* proto = p.attr("protocol")) {
                port.protocol = *proto;
            }
            if (const std::string* id = p.attr("portid")) {
                port.number = static_cast<std::uint16_t>(std::atoi(id->c_str()));
            }
            if (const XmlNode* state = p.child("state")) {
                if (const std::string* s = state->attr("state")) {
                    port.state = *s;
                }
            }
            if (const XmlNode* service = p.child("service")) {
                if (const std::string* v = service->attr("name")) {
                    port.service = *v;
                }
                if (const std::string* v = service->attr("product")) {
                    port.product = *v;
                }
                if (const std::string* v = service->attr("version")) {
                    port.version = *v;
                }
                if (const std::string* v = service->attr("extrainfo")) {
                    port.extrainfo = *v;
                }
            }
            host.ports.push_back(std::move(port));
        }
    }

    host.subnet = ipv4_subnet(host.address, 24);
    host.risk = evaluate_risk(host);
}

} // namespace

Scan NmapXmlParser::parse(std::string_view xml) {
    Scan scan;

    XmlReader reader(xml);
    const std::optional<XmlNode> root = reader.parse_document();
    if (!root.has_value() || root->name != "nmaprun") {
        return scan;
    }

    if (const std::string* version = root->attr("version")) {
        scan.nmap_version = *version;
    }
    if (const std::string* args = root->attr("args")) {
        scan.target = *args;
    }
    if (const std::string* start = root->attr("start")) {
        scan.started_at = *start;
    }

    for (const auto& node : root->children) {
        if (node.name == "host") {
            Host host;
            parse_host(node, host);
            if (!host.address.empty()) {
                scan.hosts.push_back(std::move(host));
            }
        } else if (node.name == "runstats") {
            // best effort: keep finish time if present
            if (const XmlNode* finished = node.child("finished")) {
                if (const std::string* time = finished->attr("time")) {
                    scan.finished_at = *time;
                }
            }
        }
    }

    return scan;
}

} // namespace vnm
