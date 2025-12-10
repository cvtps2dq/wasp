#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>

namespace wasp::utils {

    // --- DEBUG: Print Packet Hex ---
    inline void print_packet(const char* label, const uint8_t* data, size_t len) {
        size_t limit = len < 64 ? len : 64;
        std::cout << "[" << label << "] " << std::dec << len << " bytes: ";
        for (size_t i = 0; i < limit; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // --- BSD Kernel Checksum Algorithm ---
    // This looks simple, but the casting and folding logic is specific
    // to ensuring network-byte-order correctness on all CPUs.
    inline uint16_t bsd_checksum(const void *data, int len, uint32_t sum = 0) {
        const uint16_t *ptr = reinterpret_cast<const uint16_t *>(data);

        // Sum 16-bit words directly
        while (len > 1) {
            sum += *ptr++;
            len -= 2;
        }

        // Handle odd byte
        if (len > 0) {
            // BSD logic: treat the last byte as a zero-padded word
            uint16_t odd_byte = 0;
            *reinterpret_cast<uint8_t*>(&odd_byte) = *reinterpret_cast<const uint8_t*>(ptr);
            sum += odd_byte;
        }

        // Fold 32-bit sum to 16-bit
        while (sum >> 16) {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        // Do NOT invert here. Inversion happens at assignment.
        return static_cast<uint16_t>(sum);
    }

    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;
        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return;

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // 1. IP Header Checksum
        ip_hdr->ip_sum = 0;
        // Result must be inverted (~). No htons needed for this specific alg
        // because we summed raw memory words.
        ip_hdr->ip_sum = ~bsd_checksum(ip_hdr, ip_len, 0);

        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        // 2. Layer 4 Checksums
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            if (l4_len < sizeof(struct icmp)) return;
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);

            // Fix ICMP
            icmp_hdr->icmp_cksum = 0;
            icmp_hdr->icmp_cksum = ~bsd_checksum(l4_ptr, l4_len, 0);
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (l4_len < sizeof(struct tcphdr)) return;
            struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(l4_ptr);
            tcp_hdr->th_sum = 0;

            // TCP Pseudo Header (Src + Dst + Proto + Len)
            uint32_t sum = 0;
            // Sum Src/Dst IPs (8 bytes)
            sum = bsd_checksum(&ip_hdr->ip_src, 8, sum);
            // Proto (Big Endian 16-bit word) -> htons required to match memory layout
            sum += htons(IPPROTO_TCP);
            // Length (Big Endian 16-bit word)
            sum += htons(static_cast<uint16_t>(l4_len));

            // Final TCP Sum
            tcp_hdr->th_sum = ~bsd_checksum(l4_ptr, l4_len, sum);
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (l4_len < sizeof(struct udphdr)) return;
            struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(l4_ptr);
            udp_hdr->uh_sum = 0;

            uint32_t sum = 0;
            sum = bsd_checksum(&ip_hdr->ip_src, 8, sum);
            sum += htons(IPPROTO_UDP);
            sum += htons(static_cast<uint16_t>(l4_len));

            uint16_t result = ~bsd_checksum(l4_ptr, l4_len, sum);
            if (result == 0) result = 0xFFFF;
            udp_hdr->uh_sum = result;
        }
    }
}