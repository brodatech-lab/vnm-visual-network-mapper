#pragma once

#include <string>
#include <string_view>

#include "vnm/model.hpp"

namespace vnm {

/// Parses Nmap XML (`nmap -oX -`) into the in-memory Scan model.
///
/// The implementation is a small, dependency-free pull parser tuned for the
/// subset of XML emitted by Nmap. It is fast enough to parse multi-megabyte
/// scans in place without a DOM library.
class NmapXmlParser {
public:
    /// Throws nothing; returns an empty Scan when the input is not valid XML.
    [[nodiscard]] static Scan parse(std::string_view xml);
};

} // namespace vnm
