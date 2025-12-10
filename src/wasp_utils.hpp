#pragma once
#include <vector>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace wasp::utils {

    // --- Debugging ---
    inline void print_packet(const char* label, const uint8_t* data, size_t len) {
        // Only print first 64 bytes (Headers) to avoid spam
        size_t limit = len < 64 ? len : 64;
        std::cout << "[" << label << "] " << std::dec << len << " bytes: ";
        for (size_t i = 0; i < limit; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(data[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    // --- Standard Checksum (lwIP Style) ---
    inline uint16_t standard_chksum(const void *dataptr, int len) {
        const uint8_t *pb = reinterpret_cast<const uint8_t *>(dataptr);
        const uint16_t *ps;
        uint32_t sum = 0;
        int tlen = len;

        ps = reinterpret_cast<const uint16_t *>(pb);
        while (tlen > 1) {
            sum += *ps++;
            tlen -= 2;
        }
        if (tlen > 0) {
            // Take care of the last odd byte
            sum += *reinterpret_cast<const uint8_t *>(ps);
        }

        // Fold 32-bit sum to 16-bit
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }

    // --- Packet Fixer ---
    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;
        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return;

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // 1. IP Checksum
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = standard_chksum(packet, ip_len);

        // 2. L4 Checksum
        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        // Prepare Pseudo Header Sum
        uint32_t sum = 0;
        const uint16_t* src = reinterpret_cast<const uint16_t*>(&ip_hdr->ip_src);
        const uint16_t* dst = reinterpret_cast<const uint16_t*>(&ip_hdr->ip_dst);

        // Sum IPs
        sum += src[0]; sum += src[1];
        sum += dst[0]; sum += dst[1];

        // Sum Proto + Length (Host endian addition of 16-bit words?)
        // No, standard pseudo header logic:
        // Proto(upper 0) + Length
        sum += htons(ip_hdr->ip_p);
        sum += htons(static_cast<uint16_t>(l4_len));

        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            // ICMP v4: No Pseudo Header
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);
            icmp_hdr->icmp_cksum = 0;
            icmp_hdr->icmp_cksum = standard_chksum(l4_ptr, l4_len);
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr* th = reinterpret_cast<struct tcphdr*>(l4_ptr);
            th->th_sum = 0;

            // Add L4 data to Pseudo Sum
            const uint16_t* d = reinterpret_cast<const uint16_t*>(l4_ptr);
            int dlen = l4_len;
            while(dlen > 1) { sum += *d++; dlen -= 2; }
            if(dlen > 0) sum += *reinterpret_cast<const uint8_t*>(d);

            while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
            th->th_sum = static_cast<uint16_t>(~sum);
        }
    }
}