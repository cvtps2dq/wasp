#pragma once
#include <libwebsockets.h>
#include <mutex>
#include <map>
#include <string>
#include <vector>
#include <queue> // <--- Add this
#include "wasp_defs.hpp"

class SessionManager {
public:
    std::string register_client(struct lws* wsi);
    void unregister_client(struct lws* wsi);
    struct lws* get_wsi_for_ip(const std::string& ip_addr);

    void set_is_server(bool server) { is_server_ = server; }
    bool is_server() const { return is_server_; }

private:
    std::mutex mtx_;
    std::map<struct lws*, std::string> wsi_to_ip_map_;
    std::map<std::string, struct lws*> ip_to_wsi_map_;

    uint32_t next_new_octet_ = 2; // Start assigning from .2

    // Store freed octets to reuse them (e.g., if .2 disconnects, put 2 here)
    // Using min-priority queue to always give the lowest available IP
    std::priority_queue<uint8_t, std::vector<uint8_t>, std::greater<uint8_t>> free_octets_;

    bool is_server_ = false;
};