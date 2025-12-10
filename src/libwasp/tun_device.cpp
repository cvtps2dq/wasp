#include "tun_device.hpp"
#include "wasp_utils.hpp" // For fix_packet_checksums
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <vector>

// ==========================================
// OS-Specific Includes & Constants
// ==========================================

#if defined(__linux__)
    #include <net/if.h>
    #include <linux/if_tun.h>
#elif defined(__APPLE__)
    #include <sys/socket.h>
    #include <sys/sys_domain.h>
    #include <sys/kern_control.h>
    #include <net/if_utun.h>
    #include <netinet/in.h>

    // Fallbacks if system headers are missing specific definitions
    #ifndef UTUN_CONTROL_NAME
        #define UTUN_CONTROL_NAME "com.apple.net.utun_control"
    #endif
#endif

namespace wasp {

    // ==========================================
    // Constructor (Allocation)
    // ==========================================
    TunDevice::TunDevice(const std::string& desired_name, bool is_server)
        : is_server_(is_server) {

#if defined(__linux__)
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        // Open the clone device
        if ((fd_ = open("/dev/net/tun", O_RDWR)) < 0) {
            throw std::runtime_error("TUN: Failed to open /dev/net/tun");
        }

        // IFF_NO_PI is CRITICAL on Linux to avoid 4-byte protocol headers
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        // Try to assign the desired name (e.g., "wasp0")
        if (!desired_name.empty()) {
            strncpy(ifr.ifr_name, desired_name.c_str(), IFNAMSIZ);
        }

        if (ioctl(fd_, TUNSETIFF, (void*)&ifr) < 0) {
            close(fd_);
            throw std::runtime_error("TUN: ioctl(TUNSETIFF) failed");
        }

        name_ = ifr.ifr_name;

#elif defined(__APPLE__)
        // macOS UTUN Allocation Logic
        fd_ = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd_ < 0) {
            throw std::runtime_error("TUN: socket(PF_SYSTEM) failed");
        }

        struct ctl_info info{};
        memset(&info, 0, sizeof(info));
        strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));

        if (ioctl(fd_, CTLIOCGINFO, &info) == -1) {
            close(fd_);
            throw std::runtime_error("TUN: ioctl(CTLIOCGINFO) failed");
        }

        struct sockaddr_ctl sc{};
        memset(&sc, 0, sizeof(sc));
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = info.ctl_id;
        sc.sc_unit = 0; // Let OS pick utun0, utun1, etc.

        if (connect(fd_, reinterpret_cast<struct sockaddr *>(&sc), sizeof(sc)) == -1) {
            close(fd_);
            throw std::runtime_error("TUN: connect() failed");
        }

        char name_buf[256];
        socklen_t len = sizeof(name_buf);
        if (getsockopt(fd_, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name_buf, &len) == -1) {
            // Fallback if we can't get the name
            name_ = "utun?";
        } else {
            name_ = name_buf;
        }
#endif
    }

    // ==========================================
    // Destructor
    // ==========================================
    TunDevice::~TunDevice() {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }

    // ==========================================
    // Read
    // ==========================================
    ssize_t TunDevice::read(std::vector<uint8_t>& buffer) {
        // Ensure buffer has enough space for a jumbo packet
        if (buffer.size() < 65536) {
            buffer.resize(65536);
        }

#if defined(__linux__)
        ssize_t nread;
        do {
            // Linux: Read raw IP packets directly (Zero Copy into vector)
            nread = ::read(fd_, buffer.data(), buffer.size());
        } while (nread < 0 && errno == EINTR);

        if (nread <= 0) return nread; // Error or EOF

        // SERVER FIX: Linux Virtual Interfaces offload checksums (set to 0).
        // We must calculate them in software before encrypting.
        if (is_server_) {
            wasp::utils::fix_packet_checksums(buffer.data(), nread);
        }

        return nread;

#elif defined(__APPLE__)
        ssize_t nread;
        do {
            // macOS: Reads [4-byte Header] + [IP Packet]
            nread = ::read(fd_, buffer.data(), buffer.size());
        } while (nread < 0 && errno == EINTR);

        if (nread <= 4) return -1; // Header only or error

        // Shift data to remove the 4-byte header
        // Memmove is optimized and handles overlap safely
        uint8_t* ptr = buffer.data();
        std::memmove(ptr, ptr + 4, nread - 4);

        return nread - 4; // Return payload size
#else
        return -1;
#endif
    }

    // ==========================================
    // Write
    // ==========================================
    ssize_t TunDevice::write(const std::vector<uint8_t>& buffer) {
        if (buffer.empty()) return 0;

#if defined(__linux__)
        // Linux: Write raw IP packet
        return ::write(fd_, buffer.data(), buffer.size());

#elif defined(__APPLE__)
        // macOS: Must prepend 4-byte Protocol Family Header (Network Byte Order)
        uint32_t af = htonl(AF_INET);

        // We have to copy to a new buffer to prepend the header.
        // (Optimization note: writev() could avoid this copy, but let's keep it simple/proven for now)
        std::vector<uint8_t> p(4 + buffer.size());

        std::memcpy(p.data(), &af, 4);
        std::memcpy(p.data() + 4, buffer.data(), buffer.size());

        return ::write(fd_, p.data(), p.size());
#else
        return -1;
#endif
    }

} // namespace wasp