#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace wasp::utils {

    // Standard 1s Complement Sum
    inline uint32_t sum_range(const void* data, size_t len, uint32_t current_sum) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
        while (len > 1) {
            current_sum += *ptr++;
            len -= 2;
        }
        if (len > 0) {
            current_sum += *reinterpret_cast<const uint8_t*>(ptr);
        }
        return current_sum;
    }

    // Fold 32-bit sum to 16-bit
    inline uint16_t fold_checksum(uint32_t sum) {
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }

    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;

        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return;

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // 1. Fix IP Header Checksum
        ip_hdr->ip_sum = 0;
        uint32_t ip_sum_val = sum_range(ip_hdr, ip_len, 0);
        ip_hdr->ip_sum = fold_checksum(ip_sum_val);

        // Pointers to L4 data
        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        // 2. Fix Layer 4 Checksums
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            if (l4_len < sizeof(struct icmp)) return;
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);

            // ICMPv4 Checksum = Just the ICMP data. NO Pseudo Header.
            icmp_hdr->icmp_cksum = 0;
            uint32_t sum = sum_range(l4_ptr, l4_len, 0);
            icmp_hdr->icmp_cksum = fold_checksum(sum);
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (l4_len < sizeof(struct tcphdr)) return;
            struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(l4_ptr);

            tcp_hdr->th_sum = 0;

            // TCP Uses Pseudo Header (SrcIP + DstIP + Proto + Len)
            uint32_t sum = 0;
            sum = sum_range(&ip_hdr->ip_src, 8, sum); // Src + Dst (8 bytes contiguous)
            sum += htons(IPPROTO_TCP);
            sum += htons(static_cast<uint16_t>(l4_len));
            sum = sum_range(l4_ptr, l4_len, sum); // TCP Header + Data

            tcp_hdr->th_sum = fold_checksum(sum);
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (l4_len < sizeof(struct udphdr)) return;
            struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(l4_ptr);

            udp_hdr->uh_sum = 0;

            // UDP Uses Pseudo Header
            uint32_t sum = 0;
            sum = sum_range(&ip_hdr->ip_src, 8, sum);
            sum += htons(IPPROTO_UDP);
            sum += htons(static_cast<uint16_t>(l4_len));
            sum = sum_range(l4_ptr, l4_len, sum);

            udp_hdr->uh_sum = fold_checksum(sum);
            if (udp_hdr->uh_sum == 0) udp_hdr->uh_sum = 0xFFFF;
        }
    }
}