#include "vnm/links.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <set>

namespace vnm {
namespace {

constexpr std::size_t kMaxCveLinks = 6;

bool is_digit(char c) { return c >= '0' && c <= '9'; }

std::string service_query(const Port& port) {
    std::string query = port.product;
    if (!port.version.empty()) {
        if (!query.empty()) {
            query.push_back(' ');
        }
        query += port.version;
    }
    if (query.empty()) {
        query = port.service;
    }
    return query;
}

RefLink cve_link(const std::string& cve) {
    return RefLink{"[" + cve + "]",
                   "https://nvd.nist.gov/vuln/detail/" + url_encode(cve),
                   LinkKind::Cve};
}

} // namespace

std::vector<std::string> extract_cves(std::string_view text) {
    std::vector<std::string> result;
    std::set<std::string> seen;
    for (std::size_t i = 0; i + 4 <= text.size(); ++i) {
        if (std::toupper(static_cast<unsigned char>(text[i])) != 'C' ||
            std::toupper(static_cast<unsigned char>(text[i + 1])) != 'V' ||
            std::toupper(static_cast<unsigned char>(text[i + 2])) != 'E' ||
            text[i + 3] != '-') {
            continue;
        }
        std::size_t j = i + 4;
        std::size_t digits = 0;
        while (j < text.size() && is_digit(text[j])) {
            ++j;
            ++digits;
        }
        if (digits != 4 || j >= text.size() || text[j] != '-') {
            continue;
        }
        ++j;
        std::size_t tail = 0;
        while (j < text.size() && is_digit(text[j])) {
            ++j;
            ++tail;
        }
        if (tail < 4) {
            continue;
        }
        std::string cve(text.substr(i, j - i));
        for (char& c : cve) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        if (seen.insert(cve).second) {
            result.push_back(std::move(cve));
        }
        i = j - 1;
    }
    return result;
}

std::string url_encode(const std::string& value) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (std::isalnum(u) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(c);
        } else {
            out.push_back('%');
            out.push_back(hex[(u >> 4) & 0x0F]);
            out.push_back(hex[u & 0x0F]);
        }
    }
    return out;
}

std::vector<RefLink> port_links(const Host& /*host*/, const Port& port) {
    std::vector<RefLink> links;
    const std::string num = std::to_string(port.number);

    // Port "what is this" references.
    links.push_back({"SpeedGuide", "https://www.speedguide.net/port.php?port=" + num,
                     LinkKind::Info});
    links.push_back({"IANA",
                     "https://www.iana.org/assignments/service-names-port-numbers/"
                     "service-names-port-numbers.xhtml?search=" +
                         num,
                     LinkKind::Info});
    links.push_back({"Shodan",
                     "https://www.shodan.io/search?query=" + url_encode("port:" + num),
                     LinkKind::Info});

    // Service vulnerability search (only when we know the product/service).
    const std::string service = service_query(port);
    if (!service.empty()) {
        const std::string q = url_encode(service);
        links.push_back({"Vulners", "https://vulners.com/search?query=" + q,
                         LinkKind::Service});
        links.push_back({"NVD",
                         "https://nvd.nist.gov/vuln/search/results?query=" + q +
                             "&search_type=all",
                         LinkKind::Service});
        std::string product_query = port.product.empty() ? port.service : port.product;
        links.push_back({"Exploit-DB",
                         "https://www.exploit-db.com/search?q=" +
                             url_encode(product_query),
                         LinkKind::Exploit});
    }

    // CVEs found by NSE.
    for (std::size_t i = 0; i < port.cves.size() && i < kMaxCveLinks; ++i) {
        links.push_back(cve_link(port.cves[i]));
    }

    return links;
}

std::vector<RefLink> host_links(const Host& host) {
    std::vector<RefLink> links;
    for (std::size_t i = 0; i < host.cves.size() && i < kMaxCveLinks; ++i) {
        links.push_back(cve_link(host.cves[i]));
    }
    return links;
}

std::vector<RefLink> mac_links(const Host& host) {
    std::vector<RefLink> links;
    if (host.mac.empty()) {
        return links;
    }
    links.push_back({"MAC lookup",
                     "https://maclookup.app/search/result?mac=" + host.mac,
                     LinkKind::Info});
    return links;
}

} // namespace vnm
