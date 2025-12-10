#pragma once
#include <libwebsockets.h>
#include <mutex>
#include <map>
#include <string>

// Forward declare to avoid circular includes
struct WaspSessionData;

class SessionManager {
public:
    // Called when a new client connects
    // Returns the assigned virtual IP address
    std::string register_client(struct lws* wsi);

    // Called when a client disconnects
    void unregister_client(struct lws* wsi);

    // Finds the target client based on the destination IP of a packet from TUN
    struct lws* get_wsi_for_ip(const std::string& ip_addr);

    void set_is_server(const bool server) { is_server_ = server; }
    [[nodiscard]] bool is_server() const { return is_server_; }

private:
    std::mutex mtx_;
    // Maps a client's wsi pointer to their assigned virtual IP
    std::map<struct lws*, std::string> wsi_to_ip_map_;
    // Maps a virtual IP back to the wsi (for routing)
    std::map<std::string, struct lws*> ip_to_wsi_map_;

    // Simple IP address pool for this demo
    uint32_t next_ip_ = 2; // Start assigning from 10.0.0.2

    bool is_server_ = false;
};