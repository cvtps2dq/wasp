#pragma once
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace wasp::utils {

    // 1. Basic Internet Checksum Algorithm (RFC 1071)
    inline uint16_t checksum(const void* data, size_t len, uint32_t current_sum = 0) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
        while (len > 1) {
            current_sum += *ptr++;
            len -= 2;
        }
        if (len > 0) {
            current_sum += *reinterpret_cast<const uint8_t*>(ptr);
        }
        while (current_sum >> 16) {
            current_sum = (current_sum & 0xFFFF) + (current_sum >> 16);
        }
        return static_cast<uint16_t>(~current_sum);
    }

    // 2. Helper to calculate checksum sum (no inversion) for Pseudo Headers
    inline uint32_t checksum_partial(const void* data, size_t len, uint32_t sum) {
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(data);
        while (len > 1) {
            sum += *ptr++;
            len -= 2;
        }
        if (len > 0) {
            sum += *reinterpret_cast<const uint8_t*>(ptr);
        }
        return sum;
    }

    // 3. Finalize sum to 16-bit value
    inline uint16_t finalize_checksum(uint32_t sum) {
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return static_cast<uint16_t>(~sum);
    }

    // 4. Master Function: Parses IP and patches checksums for TCP/UDP/ICMP
    inline void fix_packet_checksums(uint8_t* packet, size_t len) {
        if (len < sizeof(struct ip)) return;

        struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet);
        if (ip_hdr->ip_v != 4) return; // Only handle IPv4 for now

        size_t ip_len = ip_hdr->ip_hl * 4;
        if (len < ip_len) return;

        // --- Fix IP Header Checksum ---
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = checksum(ip_hdr, ip_len);

        // --- Prepare for L4 Checksum (Pseudo Header) ---
        // Pseudo Header: SrcIP(4) + DstIP(4) + Zero(1) + Proto(1) + Length(2)
        uint32_t pseudo_sum = 0;
        pseudo_sum = checksum_partial(&ip_hdr->ip_src, 4, pseudo_sum);
        pseudo_sum = checksum_partial(&ip_hdr->ip_dst, 4, pseudo_sum);
        uint16_t proto_len = htons(len - ip_len);

        // Add Protocol (padded to 16 bits: 0x00 + Proto)
        uint16_t proto_part = htons(ip_hdr->ip_p);
        pseudo_sum += proto_part; // Actually just adding the byte is tricky in big endian, relying on structure

        // Let's do pseudo-sum accurately:
        // Src (4) + Dst (4) + Reserved (1=0) + Proto (1) + Length (2)
        // We can just add the raw bytes of Src/Dst/Proto/Len into the accumulator.
        pseudo_sum = 0;
        uint32_t src = ip_hdr->ip_src.s_addr;
        uint32_t dst = ip_hdr->ip_dst.s_addr;

        // Fold 32-bit addresses into 16-bit sums
        pseudo_sum += (src & 0xFFFF) + (src >> 16);
        pseudo_sum += (dst & 0xFFFF) + (dst >> 16);

        pseudo_sum += htons(ip_hdr->ip_p);
        pseudo_sum += proto_len;

        uint8_t* l4_ptr = packet + ip_len;
        size_t l4_len = len - ip_len;

        if (ip_hdr->ip_p == IPPROTO_ICMP) {
            if (l4_len < sizeof(struct icmp)) return;
            struct icmp* icmp_hdr = reinterpret_cast<struct icmp*>(l4_ptr);
            icmp_hdr->icmp_cksum = 0;
            icmp_hdr->icmp_cksum = checksum(l4_ptr, l4_len);
        }
        else if (ip_hdr->ip_p == IPPROTO_TCP) {
            if (l4_len < sizeof(struct tcphdr)) return;
            struct tcphdr* tcp_hdr = reinterpret_cast<struct tcphdr*>(l4_ptr);
            tcp_hdr->th_sum = 0;
            // Add Pseudo Sum + TCP Header/Data Sum
            uint32_t final_sum = checksum_partial(l4_ptr, l4_len, pseudo_sum);
            tcp_hdr->th_sum = finalize_checksum(final_sum);
        }
        else if (ip_hdr->ip_p == IPPROTO_UDP) {
            if (l4_len < sizeof(struct udphdr)) return;
            struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(l4_ptr);
            udp_hdr->uh_sum = 0;
            uint32_t final_sum = checksum_partial(l4_ptr, l4_len, pseudo_sum);
            udp_hdr->uh_sum = finalize_checksum(final_sum);
            if (udp_hdr->uh_sum == 0) udp_hdr->uh_sum = 0xFFFF; // RFC 768
        }
    }
}