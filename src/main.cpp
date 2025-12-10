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

    // 1. Endian-Independent Checksum (RFC 1071 compliant)
    // Treats data strictly as a stream of Big Endian 16-bit words.
    inline uint32_t calculate_sum(const uint8_t* data, size_t len, uint32_t initial_sum) {
        uint32_t sum = initial_sum;
        const uint8_t* ptr = data;

        // Sum 16-bit words
        while (len > 1) {
            // Construct 16-bit word manually: (Hi << 8) | Lo
            uint16_t word = (static_cast<uint16_t>(ptr[0]) << 8) + ptr[1];
            sum += word;
            ptr += 2;
            len -= 2;
        }

        // Handle odd byte (Padded with 0 at the end)
        if (len > 0) {
            uint16_t word = (static_cast<uint16_t>(ptr[0]) << 8);
            sum += word;
        }

        return sum;
    }

    // 2. Finalize: Fold 32-bit sum to 16-bit One's Complement
    inline uint16_t finalize_checksum(uint32_t sum) {
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // Result is already in Host Integer format corresponding to Network value
        return static_cast<uint16_t>(~sum);
    }

    // 3. Master Fixer
    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;

        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return;

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // --- Fix IP Header Checksum ---
        ip_hdr->ip_sum = 0;
        // Calculate sum of header bytes
        uint32_t ip_sum_val = calculate_sum(packet, ip_len, 0);
        // Write result in Network Byte Order
        ip_hdr->ip_sum = htons(finalize_checksum(ip_sum_val));

        // --- Prepare for L4 (Pseudo Header) ---
        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        // Pseudo Header Sum: SrcIP + DstIP + Proto + Length
        // We can cheat and just sum the bytes of the IP Header fields directly
        // because they are already in Network Byte Order.
        uint32_t pseudo_sum = 0;

        // Src IP (4 bytes)
        pseudo_sum = calculate_sum(reinterpret_cast<uint8_t*>(&ip_hdr->ip_src), 4, pseudo_sum);
        // Dst IP (4 bytes)
        pseudo_sum = calculate_sum(reinterpret_cast<uint8_t*>(&ip_hdr->ip_dst), 4, pseudo_sum);

        // Protocol (1 byte, padded to 2) -> 0x00 + Proto
        pseudo_sum += ip_hdr->ip_p;

        // L4 Length (16-bit value)
        pseudo_sum += l4_len;

        // --- Fix Layer 4 ---
        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            if (l4_len < sizeof(struct icmp)) return;
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);

            // ICMP Checksum = Only ICMP Header + Data (No Pseudo Header for IPv4)
            icmp_hdr->icmp_cksum = 0;
            uint32_t sum = calculate_sum(l4_ptr, l4_len, 0);
            icmp_hdr->icmp_cksum = htons(finalize_checksum(sum));
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (l4_len < sizeof(struct tcphdr)) return;
            struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(l4_ptr);

            tcp_hdr->th_sum = 0;
            uint32_t sum = calculate_sum(l4_ptr, l4_len, pseudo_sum);
            tcp_hdr->th_sum = htons(finalize_checksum(sum));
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (l4_len < sizeof(struct udphdr)) return;
            struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(l4_ptr);

            udp_hdr->uh_sum = 0;
            uint32_t sum = calculate_sum(l4_ptr, l4_len, pseudo_sum);
            uint16_t final = finalize_checksum(sum);
            if (final == 0) final = 0xFFFF;
            udp_hdr->uh_sum = htons(final);
        }
    }
}