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

    // --- STANDARD CHECKSUM ALGORITHM (RFC 1071) ---
    // Uses native uint16_t addition. Endian-safe via final htons().
    inline uint16_t standard_chksum(const void* data, size_t len, uint32_t current_sum = 0) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);

        while (len > 1) {
            current_sum += *ptr++;
            len -= 2;
        }

        // Handle odd byte
        if (len > 0) {
            // Depending on endianness, the odd byte is either the MSB or LSB of the last word.
            // But standard IP checksum logic simply casts it as a byte padded with zero.
            // On Little Endian, we treat it as the lower byte of a word (0x00XX).
            uint16_t odd_byte = 0;
            *reinterpret_cast<uint8_t*>(&odd_byte) = *reinterpret_cast<const uint8_t*>(ptr);
            current_sum += odd_byte;
        }

        // Fold 32-bit sum to 16-bit
        while (current_sum >> 16) {
            current_sum = (current_sum & 0xFFFF) + (current_sum >> 16);
        }

        return static_cast<uint16_t>(current_sum);
    }

    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;
        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return;

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // 1. IP Header Checksum
        ip_hdr->ip_sum = 0;
        // The standard algo result needs to be inverted (One's Complement)
        ip_hdr->ip_sum = ~standard_chksum(ip_hdr, ip_len, 0);

        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        // 2. Layer 4 Checksums
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            if (l4_len < sizeof(struct icmp)) return;
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);

            // ICMP: Checksum of Header + Data (No Pseudo Header)
            icmp_hdr->icmp_cksum = 0;
            icmp_hdr->icmp_cksum = ~standard_chksum(l4_ptr, l4_len, 0);
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (l4_len < sizeof(struct tcphdr)) return;
            struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(l4_ptr);
            tcp_hdr->th_sum = 0;

            // TCP Pseudo Header Sum
            uint32_t sum = 0;
            sum += standard_chksum(&ip_hdr->ip_src, 8, 0); // Src(4) + Dst(4)
            sum += htons(IPPROTO_TCP);
            sum += htons(static_cast<uint16_t>(l4_len));

            // Finalize with Payload
            tcp_hdr->th_sum = ~standard_chksum(l4_ptr, l4_len, sum);
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (l4_len < sizeof(struct udphdr)) return;
            struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(l4_ptr);
            udp_hdr->uh_sum = 0;

            // UDP Pseudo Header Sum
            uint32_t sum = 0;
            sum += standard_chksum(&ip_hdr->ip_src, 8, 0);
            sum += htons(IPPROTO_UDP);
            sum += htons(static_cast<uint16_t>(l4_len));

            uint16_t result = ~standard_chksum(l4_ptr, l4_len, sum);
            if (result == 0) result = 0xFFFF;
            udp_hdr->uh_sum = result;
        }
    }
}