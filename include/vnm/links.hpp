#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "vnm/model.hpp"

namespace vnm {

/// Classification of a reference link (drives the chip colour).
enum class LinkKind { Info, Service, Exploit, Cve };

/// A clickable reference chip attached to a port or host.
struct RefLink {
    std::string label;
    std::string url;
    LinkKind kind{LinkKind::Info};
};

/// Extract unique CVE identifiers ("CVE-YYYY-NNNN...") from arbitrary text.
[[nodiscard]] std::vector<std::string> extract_cves(std::string_view text);

/// Percent-encode a value for use in a URL query string.
[[nodiscard]] std::string url_encode(const std::string& value);

/// Reference links for a port: port info (SpeedGuide/IANA/Shodan), service
/// vulnerability search (Vulners/NVD/Exploit-DB) and one link per CVE.
[[nodiscard]] std::vector<RefLink> port_links(const Host& host, const Port& port);

/// Reference links for host-level findings (hostscript CVEs).
[[nodiscard]] std::vector<RefLink> host_links(const Host& host);

} // namespace vnm
