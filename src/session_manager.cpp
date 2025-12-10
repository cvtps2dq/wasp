#include "session_manager.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <array>

// Thread-safe, endian-safe IP address generation.
std::string make_ip_addr(const uint32_t index) {
    uint8_t a = 10, b = 89, c = 89;
    uint8_t d = static_cast<uint8_t>(index);

    // Use a stack-allocated buffer and snprintf for thread safety.
    std::array<char, INET_ADDRSTRLEN> buffer{};
    snprintf(buffer.data(), buffer.size(), "%d.%d.%d.%d", a, b, c, d);
    return {buffer.data()};
}

std::string SessionManager::register_client(struct lws* wsi) {
    std::lock_guard lock(mtx_);

    std::string new_ip = make_ip_addr(next_ip_++);

    wsi_to_ip_map_[wsi] = new_ip;
    ip_to_wsi_map_[new_ip] = wsi;

    std::cout << "[MANAGER] Registered client " << wsi << " with IP " << new_ip << std::endl;
    return new_ip;
}

void SessionManager::unregister_client(struct lws* wsi) {
    std::lock_guard lock(mtx_);

    if (wsi_to_ip_map_.contains(wsi)) {
        const std::string ip = wsi_to_ip_map_[wsi];
        std::cout << "[MANAGER] Unregistering client " << wsi << " with IP " << ip << std::endl;

        ip_to_wsi_map_.erase(ip);
        wsi_to_ip_map_.erase(wsi);
    }
}

struct lws* SessionManager::get_wsi_for_ip(const std::string& ip_addr) {
    std::lock_guard lock(mtx_);
    if (ip_to_wsi_map_.contains(ip_addr)) {
        return ip_to_wsi_map_[ip_addr];
    }
    std::cout << "[MANAGER] *** IP lookup failed for: " << ip_addr << " ***" << std::endl;
    return nullptr;
}