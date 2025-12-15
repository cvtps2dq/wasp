//
// Created by cv2 on 15.12.2025.
//

#pragma once
#include <string>
#include <string_view>
#include <utility> // For std::pair

// ==========================================
// SHARED DEFINITIONS FOR GUI & NETWORK
// ==========================================

// LogLevel Enum
enum class LogLevel { INFO, SUCCESS, WARN, ERROR, DEBUG, TRAFFIC, CMD };

// Parsed Address Struct
struct ParsedAddress {
    std::string host;
    int port;
};

// Address Parser Function
inline ParsedAddress parse_address(std::string_view full_address) {
    size_t colon_pos = full_address.find(':');
    if (colon_pos != std::string_view::npos) {
        std::string host(full_address.substr(0, colon_pos));
        int port = std::stoi(std::string(full_address.substr(colon_pos + 1)));
        return {host, port};
    }
    // No port specified, use default
    return {std::string(full_address), 7681};
}
