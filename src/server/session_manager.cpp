#include "session_manager.hpp"
#include <arpa/inet.h>
#include <iostream>
#include <array>
#include <format> // C++20

std::string make_ip_addr(uint8_t last_octet) {
    // Hardcoded subnet 10.89.89.x for now
    return std::format("10.89.89.{}", last_octet);
}

std::string SessionManager::register_client(struct lws* wsi) {
    std::lock_guard<std::mutex> lock(mtx_);

    uint8_t octet;

    // 1. Check if we have recycled IPs available
    if (!free_octets_.empty()) {
        octet = free_octets_.top();
        free_octets_.pop();
    }
    // 2. Otherwise use the next new one
    else {
        if (next_new_octet_ > 254) {
            // Simple protection against exhaustion
            std::cerr << "[MANAGER] CRITICAL: Subnet 10.89.89.0/24 is FULL!" << std::endl;
            return "";
        }
        octet = next_new_octet_++;
    }

    std::string new_ip = make_ip_addr(octet);

    wsi_to_ip_map_[wsi] = new_ip;
    ip_to_wsi_map_[new_ip] = wsi;

    return new_ip;
}

void SessionManager::unregister_client(struct lws* wsi) {
    std::lock_guard<std::mutex> lock(mtx_);

    if (wsi_to_ip_map_.count(wsi)) {
        std::string ip = wsi_to_ip_map_[wsi];

        // Extract the last octet to recycle it
        size_t last_dot = ip.find_last_of('.');
        if (last_dot != std::string::npos) {
            int val = std::stoi(ip.substr(last_dot + 1));
            if (val > 1 && val < 255) {
                free_octets_.push(static_cast<uint8_t>(val));
                std::cout << "[MANAGER] Recycled IP octet ." << val << std::endl;
            }
        }

        ip_to_wsi_map_.erase(ip);
        wsi_to_ip_map_.erase(wsi);
    }
}

struct lws* SessionManager::get_wsi_for_ip(const std::string& ip_addr) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = ip_to_wsi_map_.find(ip_addr);
    if (it != ip_to_wsi_map_.end()) {
        return it->second;
    }
    return nullptr;
}