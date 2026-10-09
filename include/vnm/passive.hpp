#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vnm {

/// A capture device as reported by libpcap/Npcap.
struct CaptureDevice {
    std::string name;        // pcap name (e.g. "eth0" or "\Device\NPF_{GUID}")
    std::string description; // human readable (may be empty)
};

/// One piece of information passively observed on the wire.
struct PassiveObservation {
    std::string ip;
    std::string mac;
    std::string hostname;
    std::string vendor;     // DHCP option 60 (vendor class identifier)
    std::string source;     // "arp" or "dhcp"
    std::int64_t first_seen{0}; // unix seconds
    std::int64_t last_seen{0};
    unsigned count{0};
    bool has_ip{false};
};

/// Decode a full Ethernet frame. Return true when an ARP sighting was found.
/// Pure function (no libpcap), safe to unit test.
[[nodiscard]] bool decode_arp(const std::uint8_t* frame, std::size_t length,
                              PassiveObservation& out);

/// Decode a full Ethernet frame. Return true when a DHCP sighting was found.
[[nodiscard]] bool decode_dhcp(const std::uint8_t* frame, std::size_t length,
                               PassiveObservation& out);

/// Background passive sniffer (ARP + DHCP) built on libpcap.
///
/// When VNM is built without libpcap (e.g. Windows without the Npcap SDK),
/// supported() returns false and start() fails with a clear message.
class PassiveScanner {
public:
    using Callback = std::function<void(const PassiveObservation&)>;

    PassiveScanner();
    ~PassiveScanner();

    PassiveScanner(const PassiveScanner&) = delete;
    PassiveScanner& operator=(const PassiveScanner&) = delete;

    /// True when the binary was compiled with libpcap support.
    [[nodiscard]] static bool supported() noexcept;

    /// Capture devices available through libpcap/Npcap (empty when unsupported).
    [[nodiscard]] static std::vector<CaptureDevice> devices();

    /// Open `device` (interface name) and start capturing on a worker thread.
    bool start(const std::string& device, Callback on_observation,
               std::string* error = nullptr);

    /// Stop the worker thread (idempotent).
    void stop();

    [[nodiscard]] bool running() const noexcept;

    /// Number of packets decoded since start().
    [[nodiscard]] std::uint64_t packets() const noexcept;

private:
    struct Impl;
    Impl* impl_{nullptr};
};

} // namespace vnm
