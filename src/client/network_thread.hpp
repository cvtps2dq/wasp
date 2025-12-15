#pragma once
#include <string>
#include <atomic>
#include <vector>
#include <mutex>
#include <queue>
#include <chrono>

#include <libwebsockets.h>
#include "common.hpp"
#include "tun_device.hpp"
#include "wasp_session.hpp"
#include "worker_pool.hpp"

struct lws;
enum lws_callback_reasons;

// ==========================================
// AppState (Shared State between GUI and Network Thread)
// ==========================================
struct AppState {
    // --- Config (Set by GUI, Read by Network) ---
    std::string server_host = "127.0.0.1";
    int server_port = 7681;
    std::string username = "";
    std::string password = "";
    std::vector<std::string> excluded_ips;

    // --- Status (Set by Network, Read by GUI) ---
    enum class Status { DISCONNECTED, CONNECTING, CONNECTED, FAILED };
    std::atomic<Status> connection_status = Status::DISCONNECTED;
    std::atomic<uint64_t> bytes_sent = 0;
    std::atomic<uint64_t> bytes_received = 0;
    std::string assigned_ip;

    // --- Control (Set by GUI, Read by Network) ---
    std::atomic<bool> connect_request = false;
    std::atomic<bool> disconnect_request = false;
    std::atomic<bool> exit_requested = false;

    // --- Logging ---
    ThreadSafeQueue<std::pair<LogLevel, std::string>> log_queue;

    // --- Network Internal (Managed by Network Thread) ---
    std::unique_ptr<wasp::TunDevice> tun;
    std::unique_ptr<WorkerPool> workers;

    wasp::Session session{wasp::Role::CLIENT};
    std::string original_gateway_ip;
    std::string server_resolved_ip;

    struct lws* wsi = nullptr;
    struct lws_context* lws_ctx = nullptr;
    std::atomic<bool> fatal_auth_error{false};

    std::atomic<bool> tunnel_ready{false};

    // Tracks if the user wants the VPN to be active.
    // Prevents auto-connection on startup and allows reconnection only if desired.
    std::atomic<bool> maintain_connection{false};

    int retry_count = 0;
    std::chrono::steady_clock::time_point next_reconnect_time;
};

void network_thread_main(AppState* state);