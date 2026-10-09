#include "vnm/export.hpp"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace vnm {
namespace {

struct JVal {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type{Null};
    bool boolean{false};
    double number{0.0};
    std::string text;
    std::vector<JVal> array;
    std::vector<std::pair<std::string, JVal>> object;

    [[nodiscard]] const JVal* find(const std::string& key) const {
        if (type != Obj) {
            return nullptr;
        }
        for (const auto& kv : object) {
            if (kv.first == key) {
                return &kv.second;
            }
        }
        return nullptr;
    }
    [[nodiscard]] std::string str(const std::string& key) const {
        const JVal* v = find(key);
        return (v != nullptr && v->type == Str) ? v->text : std::string();
    }
    [[nodiscard]] int integer(const std::string& key) const {
        const JVal* v = find(key);
        return (v != nullptr && v->type == Num) ? static_cast<int>(v->number) : 0;
    }
};

class Parser {
public:
    explicit Parser(const std::string& text) : s_(text) {}

    bool parse(JVal& out) {
        skip_ws();
        if (!parse_value(out)) {
            return false;
        }
        skip_ws();
        if (i_ < s_.size()) {
            return fail("trailing data");
        }
        return true;
    }
    [[nodiscard]] const std::string& error() const { return error_; }

private:
    const std::string& s_;
    std::size_t i_{0};
    std::string error_;

    bool fail(const char* message) {
        if (error_.empty()) {
            error_ = message;
        }
        return false;
    }

    void skip_ws() {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' ||
                                  s_[i_] == '\r')) {
            ++i_;
        }
    }

    bool parse_value(JVal& out) {
        skip_ws();
        if (i_ >= s_.size()) {
            return fail("unexpected end of input");
        }
        const char c = s_[i_];
        if (c == '{') {
            return parse_object(out);
        }
        if (c == '[') {
            return parse_array(out);
        }
        if (c == '"') {
            out.type = JVal::Str;
            return parse_string(out.text);
        }
        if (c == 't') {
            if (s_.compare(i_, 4, "true") == 0) {
                i_ += 4;
                out.type = JVal::Bool;
                out.boolean = true;
                return true;
            }
            return fail("bad literal");
        }
        if (c == 'f') {
            if (s_.compare(i_, 5, "false") == 0) {
                i_ += 5;
                out.type = JVal::Bool;
                out.boolean = false;
                return true;
            }
            return fail("bad literal");
        }
        if (c == 'n') {
            if (s_.compare(i_, 4, "null") == 0) {
                i_ += 4;
                out.type = JVal::Null;
                return true;
            }
            return fail("bad literal");
        }
        return parse_number(out);
    }

    bool parse_number(JVal& out) {
        const char* start = s_.c_str() + i_;
        char* end = nullptr;
        const double value = std::strtod(start, &end);
        if (end == start) {
            return fail("bad number");
        }
        i_ += static_cast<std::size_t>(end - start);
        out.type = JVal::Num;
        out.number = value;
        return true;
    }

    bool parse_string(std::string& out) {
        if (s_[i_] != '"') {
            return fail("expected string");
        }
        ++i_;
        while (i_ < s_.size()) {
            const char c = s_[i_++];
            if (c == '"') {
                return true;
            }
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (i_ >= s_.size()) {
                return fail("bad escape");
            }
            const char e = s_[i_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    if (i_ + 4 > s_.size()) {
                        return fail("bad \\u escape");
                    }
                    unsigned cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s_[i_++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') {
                            cp |= static_cast<unsigned>(h - '0');
                        } else if (h >= 'a' && h <= 'f') {
                            cp |= static_cast<unsigned>(h - 'a' + 10);
                        } else if (h >= 'A' && h <= 'F') {
                            cp |= static_cast<unsigned>(h - 'A' + 10);
                        } else {
                            return fail("bad hex in \\u");
                        }
                    }
                    if (cp < 0x80) {
                        out.push_back(static_cast<char>(cp));
                    } else if (cp < 0x800) {
                        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    }
                    break;
                }
                default:
                    return fail("bad escape");
            }
        }
        return fail("unterminated string");
    }

    bool parse_array(JVal& out) {
        out.type = JVal::Arr;
        ++i_; // '['
        skip_ws();
        if (i_ < s_.size() && s_[i_] == ']') {
            ++i_;
            return true;
        }
        for (;;) {
            JVal item;
            if (!parse_value(item)) {
                return false;
            }
            out.array.push_back(std::move(item));
            skip_ws();
            if (i_ >= s_.size()) {
                return fail("unterminated array");
            }
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == ']') {
                ++i_;
                return true;
            }
            return fail("expected ',' or ']'");
        }
    }

    bool parse_object(JVal& out) {
        out.type = JVal::Obj;
        ++i_; // '{'
        skip_ws();
        if (i_ < s_.size() && s_[i_] == '}') {
            ++i_;
            return true;
        }
        for (;;) {
            skip_ws();
            std::string key;
            if (!parse_string(key)) {
                return false;
            }
            skip_ws();
            if (i_ >= s_.size() || s_[i_] != ':') {
                return fail("expected ':'");
            }
            ++i_;
            JVal value;
            if (!parse_value(value)) {
                return false;
            }
            out.object.emplace_back(std::move(key), std::move(value));
            skip_ws();
            if (i_ >= s_.size()) {
                return fail("unterminated object");
            }
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == '}') {
                ++i_;
                return true;
            }
            return fail("expected ',' or '}'");
        }
    }
};

HostStatus status_from(const std::string& text) {
    if (text == "up") {
        return HostStatus::Up;
    }
    if (text == "down") {
        return HostStatus::Down;
    }
    return HostStatus::Unknown;
}

RiskLevel risk_from(const std::string& text) {
    if (text == "safe") {
        return RiskLevel::Safe;
    }
    if (text == "warning") {
        return RiskLevel::Warning;
    }
    if (text == "critical") {
        return RiskLevel::Critical;
    }
    if (text == "offline") {
        return RiskLevel::Offline;
    }
    return RiskLevel::Unknown;
}

} // namespace

bool import_scan_json(const std::string& text, Scan& out, std::string* error) {
    Parser parser(text);
    JVal root;
    if (!parser.parse(root)) {
        if (error != nullptr) {
            *error = "JSON parse error: " + parser.error();
        }
        return false;
    }
    if (root.type != JVal::Obj) {
        if (error != nullptr) {
            *error = "JSON root is not an object";
        }
        return false;
    }

    Scan scan;
    scan.target = root.str("target");
    scan.nmap_version = root.str("nmap_version");
    scan.started_at = root.str("started_at");
    scan.finished_at = root.str("finished_at");

    const JVal* hosts = root.find("hosts");
    if (hosts != nullptr && hosts->type == JVal::Arr) {
        for (const JVal& h : hosts->array) {
            if (h.type != JVal::Obj) {
                continue;
            }
            Host host;
            host.address = h.str("address");
            host.mac = h.str("mac");
            host.vendor = h.str("vendor");
            host.hostname = h.str("hostname");
            host.os_name = h.str("os");
            host.os_confidence = h.integer("os_confidence");
            host.status = status_from(h.str("status"));
            host.subnet = h.str("subnet");

            const JVal* ports = h.find("ports");
            if (ports != nullptr && ports->type == JVal::Arr) {
                for (const JVal& p : ports->array) {
                    if (p.type != JVal::Obj) {
                        continue;
                    }
                    Port port;
                    port.number = static_cast<std::uint16_t>(p.integer("number"));
                    port.protocol = p.str("protocol");
                    port.state = p.str("state");
                    port.service = p.str("service");
                    port.product = p.str("product");
                    port.version = p.str("version");
                    host.ports.push_back(std::move(port));
                }
            }

            const RiskLevel risk = risk_from(h.str("risk"));
            host.risk = risk != RiskLevel::Unknown ? risk : evaluate_risk(host);
            if (host.subnet.empty() && !host.address.empty()) {
                host.subnet = subnet_of(host.address, 24);
            }
            if (!host.address.empty()) {
                scan.hosts.push_back(std::move(host));
            }
        }
    }

    out = std::move(scan);
    return true;
}

} // namespace vnm
