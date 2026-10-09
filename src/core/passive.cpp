#include "vnm/passive.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>

#if defined(VNM_HAVE_PCAP)
#if defined(_WIN32) && !defined(WPCAP)
#define WPCAP
#endif
#include <atomic>
#include <thread>
#include <pcap.h>
#endif

namespace vnm {
namespace {

std::uint16_t read_be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

std::uint32_t read_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

std::string mac_to_string(const std::uint8_t* mac, std::size_t length) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (std::size_t i = 0; i < length; ++i) {
        if (i != 0) {
            out.push_back(':');
        }
        out.push_back(hex[(mac[i] >> 4) & 0x0F]);
        out.push_back(hex[mac[i] & 0x0F]);
    }
    return out;
}

std::string ipv4_to_string(const std::uint8_t* ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
           std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

bool ipv4_is_zero(const std::uint8_t* ip) {
    return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

} // namespace

bool decode_arp(const std::uint8_t* frame, std::size_t length,
                PassiveObservation& out) {
    constexpr std::size_t kEthernet = 14;
    constexpr std::size_t kArp = 28;
    if (length < kEthernet + kArp || read_be16(frame + 12) != 0x0806) {
        return false;
    }
    const std::uint8_t* arp = frame + kEthernet;
    if (read_be16(arp) != 0x0001 ||      // hardware type: Ethernet
        read_be16(arp + 2) != 0x0800 ||  // protocol type: IPv4
        arp[4] != 6 || arp[5] != 4) {    // MAC / IPv4 lengths
        return false;
    }
    // sender hardware / protocol address (who the sender is)
    out.mac = mac_to_string(arp + 8, 6);
    out.ip = ipv4_to_string(arp + 14);
    out.has_ip = !ipv4_is_zero(arp + 14);
    out.source = "arp";
    return !out.mac.empty();
}

bool decode_dhcp(const std::uint8_t* frame, std::size_t length,
                 PassiveObservation& out) {
    constexpr std::size_t kEthernet = 14;
    if (length < kEthernet + 20 || read_be16(frame + 12) != 0x0800) {
        return false; // not IPv4
    }
    const std::uint8_t* ip = frame + kEthernet;
    const std::size_t ihl = static_cast<std::size_t>(ip[0] & 0x0F) * 4;
    if (ihl < 20 || ip[9] != 17) {
        return false; // not UDP
    }
    if (kEthernet + ihl + 8 > length) {
        return false;
    }
    const std::uint8_t* udp = ip + ihl;
    const std::uint16_t sport = read_be16(udp);
    const std::uint16_t dport = read_be16(udp + 2);
    const bool dhcp_ports =
        (sport == 67 && dport == 68) || (sport == 68 && dport == 67);
    if (!dhcp_ports) {
        return false;
    }

    const std::uint8_t* bootp = udp + 8;
    const std::size_t bootp_len = length - (kEthernet + ihl + 8);
    constexpr std::size_t kBootpFixed = 236; // up to (excluding) the magic cookie
    if (bootp_len < kBootpFixed + 4 || read_be32(bootp + 236) != 0x63825363) {
        return false;
    }

    std::uint8_t hlen = bootp[2];
    if (hlen < 1 || hlen > 6) {
        hlen = 6;
    }
    out.mac = mac_to_string(bootp + 28, hlen); // chaddr
    out.source = "dhcp";

    const std::uint8_t* ciaddr = bootp + 12;
    const std::uint8_t* yiaddr = bootp + 16;
    std::array<std::uint8_t, 4> requested{};
    bool have_requested = false;

    const std::uint8_t* opt = bootp + 240;
    std::size_t remaining = bootp_len - 240;
    std::size_t i = 0;
    while (i < remaining) {
        const std::uint8_t code = opt[i];
        if (code == 0) {
            ++i;
            continue;
        }
        if (code == 255) {
            break;
        }
        if (i + 1 >= remaining) {
            break;
        }
        const std::uint8_t opt_len = opt[i + 1];
        if (i + 2 + opt_len > remaining) {
            break;
        }
        const std::uint8_t* value = opt + i + 2;
        switch (code) {
            case 12: // host name
                out.hostname.assign(reinterpret_cast<const char*>(value), opt_len);
                break;
            case 60: // vendor class identifier
                out.vendor.assign(reinterpret_cast<const char*>(value), opt_len);
                break;
            case 50: // requested IP address
                if (opt_len == 4) {
                    std::memcpy(requested.data(), value, 4);
                    have_requested = true;
                }
                break;
            default:
                break;
        }
        i += 2 + opt_len;
    }

    if (!ipv4_is_zero(yiaddr)) {
        out.ip = ipv4_to_string(yiaddr);
        out.has_ip = true;
    } else if (!ipv4_is_zero(ciaddr)) {
        out.ip = ipv4_to_string(ciaddr);
        out.has_ip = true;
    } else if (have_requested) {
        out.ip = ipv4_to_string(requested.data());
        out.has_ip = true;
    } else {
        out.has_ip = false;
    }
    return !out.mac.empty();
}

#if defined(VNM_HAVE_PCAP)

struct PassiveScanner::Impl {
    pcap_t* handle{nullptr};
    std::thread thread;
    std::atomic<bool> running{false};
    std::atomic<std::uint64_t> packets{0};
    Callback callback;
    int linktype{0};

    void loop() {
        while (running.load()) {
            pcap_pkthdr* header = nullptr;
            const u_char* data = nullptr;
            const int rc = pcap_next_ex(handle, &header, &data);
            if (rc == 0) {
                continue; // read timeout
            }
            if (rc < 0) {
                break; // error / EOF
            }
            packets.fetch_add(1);
            if (linktype != DLT_EN10MB) {
                continue;
            }
            PassiveObservation observation;
            if (decode_arp(data, header->caplen, observation) ||
                decode_dhcp(data, header->caplen, observation)) {
                const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                observation.first_seen = now;
                observation.last_seen = now;
                observation.count = 1;
                if (callback) {
                    callback(observation);
                }
            }
        }
    }
};

PassiveScanner::PassiveScanner() : impl_(new Impl) {}

PassiveScanner::~PassiveScanner() {
    stop();
    delete impl_;
}

bool PassiveScanner::supported() noexcept { return true; }

std::vector<CaptureDevice> PassiveScanner::devices() {
    std::vector<CaptureDevice> result;
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        return result;
    }
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        CaptureDevice device;
        device.name = dev->name != nullptr ? dev->name : "";
        device.description = dev->description != nullptr ? dev->description : "";
        if (!device.name.empty()) {
            result.push_back(std::move(device));
        }
    }
    pcap_freealldevs(alldevs);
    return result;
}

bool PassiveScanner::running() const noexcept {
    return impl_ != nullptr && impl_->running.load();
}

std::uint64_t PassiveScanner::packets() const noexcept {
    return impl_ != nullptr ? impl_->packets.load() : 0;
}

bool PassiveScanner::start(const std::string& device, Callback on_observation,
                           std::string* error) {
    if (impl_ == nullptr) {
        if (error != nullptr) {
            *error = "scanner not initialized";
        }
        return false;
    }
    if (impl_->running.load()) {
        if (error != nullptr) {
            *error = "already running";
        }
        return false;
    }
    if (device.empty()) {
        if (error != nullptr) {
            *error = "no capture device selected";
        }
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_create(device.c_str(), errbuf);
    if (handle == nullptr) {
        if (error != nullptr) {
            *error = errbuf;
        }
        return false;
    }
    pcap_set_snaplen(handle, 65535);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 200);
    if (pcap_activate(handle) != 0) {
        if (error != nullptr) {
            *error = pcap_geterr(handle);
        }
        pcap_close(handle);
        return false;
    }

    bpf_program program{};
    const char* filter = "arp or (udp and (port 67 or port 68))";
    if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        if (error != nullptr) {
            *error = pcap_geterr(handle);
        }
        pcap_close(handle);
        return false;
    }
    const int set = pcap_setfilter(handle, &program);
    pcap_freecode(&program);
    if (set != 0) {
        if (error != nullptr) {
            *error = pcap_geterr(handle);
        }
        pcap_close(handle);
        return false;
    }

    impl_->linktype = pcap_datalink(handle);
    impl_->handle = handle;
    impl_->callback = std::move(on_observation);
    impl_->packets.store(0);
    impl_->running.store(true);
    impl_->thread = std::thread([this]() { impl_->loop(); });
    return true;
}

void PassiveScanner::stop() {
    if (impl_ == nullptr) {
        return;
    }
    if (impl_->running.exchange(false)) {
        if (impl_->thread.joinable()) {
            impl_->thread.join();
        }
    }
    if (impl_->handle != nullptr) {
        pcap_close(impl_->handle);
        impl_->handle = nullptr;
    }
}

#else // no libpcap

struct PassiveScanner::Impl {};

PassiveScanner::PassiveScanner() : impl_(new Impl) {}

PassiveScanner::~PassiveScanner() { delete impl_; }

bool PassiveScanner::supported() noexcept { return false; }

std::vector<CaptureDevice> PassiveScanner::devices() { return {}; }

bool PassiveScanner::running() const noexcept { return false; }

std::uint64_t PassiveScanner::packets() const noexcept { return 0; }

bool PassiveScanner::start(const std::string&, Callback, std::string* error) {
    if (error != nullptr) {
        *error = "passive discovery not available (built without libpcap/Npcap)";
    }
    return false;
}

void PassiveScanner::stop() {}

#endif

} // namespace vnm
