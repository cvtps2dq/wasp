/**
 * WASP Server
 * High-Performance L3 VPN Server
 * v1.5 - With Flow Control & Backpressure
 */

#include <libwebsockets.h>
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <string>
#include <csignal>
#include <mutex>
#include <iomanip>
#include <format>
#include <new>
#include <cstdio>

// Internal Library Includes
#include "wasp_session.hpp"
#include "worker_pool.hpp"
#include "tun_device.hpp"
#include "session_manager.hpp"
#include "wasp_utils.hpp"
#include "db_manager.hpp"

// ==========================================
// Beautification & Logging
// ==========================================
namespace Color {
    const char* RESET   = "\033[0m";
    const char* RED     = "\033[31m";
    const char* GREEN   = "\033[32m";
    const char* YELLOW  = "\033[33m";
    const char* BLUE    = "\033[34m";
    const char* MAGENTA = "\033[35m";
    const char* CYAN    = "\033[36m";
    const char* BOLD    = "\033[1m";
}

enum class LogLevel { INFO, SUCCESS, WARN, ERROR, DEBUG, TRAFFIC };

void log(LogLevel level, const std::string& msg) {
    std::cout << Color::BOLD << "[";
    switch (level) {
        case LogLevel::INFO:    std::cout << Color::BLUE   << "INFO"; break;
        case LogLevel::SUCCESS: std::cout << Color::GREEN  << " OK "; break;
        case LogLevel::WARN:    std::cout << Color::YELLOW << "WARN"; break;
        case LogLevel::ERROR:   std::cout << Color::RED    << "ERR "; break;
        case LogLevel::DEBUG:   std::cout << Color::MAGENTA<< "DBUG"; break;
        case LogLevel::TRAFFIC: std::cout << Color::CYAN   << "TRAF"; break;
    }
    std::cout << Color::RESET << Color::BOLD << "] " << Color::RESET << msg << std::endl;
}

void print_banner() {
    std::cout << Color::MAGENTA << R"(
__/\\\______________/\\\_____/\\\\\\\\\________/\\\\\\\\\\\____/\\\\\\\\\\\\\___
 _\/\\\_____________\/\\\___/\\\\\\\\\\\\\____/\\\/////////\\\_\/\\\/////////\\\_
  _\/\\\_____________\/\\\__/\\\/////////\\\__\//\\\______\///__\/\\\_______\/\\\_
   _\//\\\____/\\\____/\\\__\/\\\_______\/\\\___\////\\\_________\/\\\\\\\\\\\\\/__
    __\//\\\__/\\\\\__/\\\___\/\\\\\\\\\\\\\\\______\////\\\______\/\\\/////////____
     ___\//\\\/\\\/\\\/\\\____\/\\\/////////\\\_________\////\\\___\/\\\_____________
      ____\//\\\\\\//\\\\\_____\/\\\_______\/\\\__/\\\______\//\\\__\/\\\_____________
       _____\//\\\__\//\\\______\/\\\_______\/\\\_\///\\\\\\\\\\\/___\/\\\_____________
        ______\///____\///_______\///________\///____\///////////_____\///______________
         Web Augmented Secure Protocol Server v1.5 — cv2 — lumen-rsg                2025
    )" << Color::RESET << std::endl;
}

// ==========================================
// Session Data (Per-Client Context)
// ==========================================
struct WaspSessionData {
    wasp::Session session;
    wasp::ByteBuffer rx_buffer;
    std::queue<wasp::ByteBuffer> handshake_tx_queue;
    std::queue<wasp::ByteBuffer> encrypted_tx_queue;
    std::string virtual_ip;

    WaspSessionData() : session(wasp::Role::SERVER) {}
};

// ==========================================
// Global Context
// ==========================================
struct ServerContext {
    std::unique_ptr<wasp::TunDevice> tun;
    std::unique_ptr<WorkerPool> workers;
    std::unique_ptr<wasp::db::UserManager> db;
    SessionManager sessions;

    struct lws_context* lws_ctx = nullptr;
    std::atomic<bool> running{true};

    // Configuration
    std::string tun_name = "wasp0";
    std::string tun_ip = "10.89.89.1";
    std::string tun_cidr = "24";
};

ServerContext app;

void sigint_handler(int) {
    log(LogLevel::WARN, "Interrupt received. Shutting down...");
    app.running = false;
    lws_cancel_service(app.lws_ctx);
}

// ==========================================
// Helper: System Commands
// ==========================================
void run_command(const std::string& cmd) {
    // log(LogLevel::DEBUG, "CMD: " + cmd);
    int ret = system(cmd.c_str());
    if (ret != 0) log(LogLevel::WARN, "Command returned non-zero exit code.");
}

std::string get_wan_interface() {
    std::string interface;
    std::array<char, 256> buffer;
    FILE* pipe = popen("ip route get 8.8.8.8", "r");
    if (!pipe) return "";

    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string result(buffer.data());
        std::stringstream ss(result);
        std::string word;
        while (ss >> word) {
            if (word == "dev") {
                ss >> interface;
                break;
            }
        }
    }
    pclose(pipe);
    return interface;
}

void configure_networking() {
    log(LogLevel::INFO, "Configuring Network Stack...");

#if defined(__linux__)
    run_command("ip addr add " + app.tun_ip + "/" + app.tun_cidr + " dev " + app.tun_name);

    // 1. Safe MTU
    run_command("ip link set dev " + app.tun_name + " mtu 1280");
    run_command("ip link set " + app.tun_name + " up");

    // 2. IP Forwarding
    run_command("sysctl -w net.ipv4.ip_forward=1 > /dev/null");

    // 3. NAT (Masquerading)
    std::string wan_iface = get_wan_interface();
    if (!wan_iface.empty()) {
        log(LogLevel::INFO, "Using '" + wan_iface + "' as WAN interface for NAT.");
        run_command("iptables -t nat -A POSTROUTING -o " + wan_iface + " -j MASQUERADE");
        run_command("iptables -A FORWARD -i " + app.tun_name + " -j ACCEPT");
        run_command("iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT");
    }

    // 4. Disable Offloading (Critical for Virtual Interfaces)
    run_command("ethtool -K " + app.tun_name + " tx off sg off tso off gro off gso off > /dev/null 2>&1");

#elif defined(__APPLE__)
    run_command("ifconfig " + app.tun_name + " " + app.tun_ip + " " + app.tun_ip + " up");
    run_command("ifconfig " + app.tun_name + " mtu 1280");
#endif

    log(LogLevel::SUCCESS, "Networking Configured. Listening on " + app.tun_ip);
}

void cleanup_networking() {
    log(LogLevel::INFO, "Restoring network configuration...");
    #if defined(__linux__)
    std::string wan_iface = get_wan_interface();
    if (!wan_iface.empty()) {
        run_command("iptables -t nat -D POSTROUTING -o " + wan_iface + " -j MASQUERADE > /dev/null 2>&1");
        run_command("iptables -D FORWARD -i " + app.tun_name + " -j ACCEPT > /dev/null 2>&1");
        run_command("iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT > /dev/null 2>&1");
    }
    #endif
    log(LogLevel::SUCCESS, "Network configuration restored.");
}

// ==========================================
// TUN Reader Thread (Routing)
// ==========================================
void tun_reader_thread() {
    log(LogLevel::INFO, "TUN Reader thread started.");

    std::vector<uint8_t> buffer(65536);

    while (app.running) {

        // === FLOW CONTROL (BACKPRESSURE) ===
        // If the worker result queue is getting too full (> 2000 packets),
        // it means we are reading from TUN faster than we can write to Clients.
        // Sleep briefly to let LWS/Clients catch up.
        if (app.workers->results.size() > 2000) {
            // Yield CPU slice but stay ready (latency < 1ms)
            std::this_thread::yield();
            continue;
        }
        // ===================================

        // TunDevice::read handles Server Checksum Fixing internally
        ssize_t nread = app.tun->read(buffer);

        if (!app.running) break;
        if (nread <= 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        wasp::ByteSpan packet_span(buffer.data(), nread);
        std::string dst_ip = wasp::utils::get_dst_ip(packet_span);

        if (dst_ip.empty()) continue;

        // Filter Noise (Multicast/Broadcast)
        if (dst_ip.length() >= 4 && (
            dst_ip.rfind("224.", 0) == 0 ||
            dst_ip.rfind("239.", 0) == 0 ||
            dst_ip == "255.255.255.255")) {
            continue;
        }

        // Routing Lookup
        struct lws* target_wsi = app.sessions.get_wsi_for_ip(dst_ip);

        if (target_wsi) {
            auto* pss = (WaspSessionData*)lws_wsi_user(target_wsi);
            if (pss && pss->session.is_established()) {

                auto key_span = pss->session.get_session_key();
                std::vector<uint8_t> key(key_span.begin(), key_span.end());
                std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + nread);

                app.workers->submit_task({
                    true, // is_encrypt
                    std::move(packet),
                    pss->session.get_session_id(),
                    wasp::InnerCommand::IPV4,
                    std::move(key),
                    target_wsi
                });

                lws_cancel_service(app.lws_ctx);
            }
        }
    }
    log(LogLevel::INFO, "TUN Reader thread stopped.");
}

// ==========================================
// LWS Callback
// ==========================================
static int callback_wasp(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len) {

    auto *pss = (WaspSessionData *)user;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            new (pss) WaspSessionData();

            // Link Auth Validator
            pss->session.set_validator([](const std::string& u, const std::string& p) {
                bool ok = app.db->authenticate(u, p);
                if (ok) log(LogLevel::SUCCESS, "Auth Success: " + u);
                else    log(LogLevel::WARN, "Auth Failed: " + u);
                return ok;
            });

            pss->virtual_ip = app.sessions.register_client(wsi);
            pss->session.set_assigned_ip(pss->virtual_ip);
            pss->session.set_session_id(reinterpret_cast<uintptr_t>(wsi));

            log(LogLevel::INFO, "Client Connected. Assigned IP: " + pss->virtual_ip);
            break;
        }

        case LWS_CALLBACK_CLOSED:
            if (pss) {
                log(LogLevel::INFO, "Client Disconnected: " + pss->virtual_ip);
                app.sessions.unregister_client(wsi);
                pss->~WaspSessionData();
            }
            break;

        case LWS_CALLBACK_RECEIVE: {
            if (!lws_frame_is_binary(wsi)) {
                std::string msg((char*)in, len);
                try {
                    auto reply = pss->session.handle_handshake_msg(msg);
                    if (reply) {
                        wasp::ByteBuffer buf(reply->begin(), reply->end());
                        pss->handshake_tx_queue.push(std::move(buf));
                        lws_callback_on_writable(wsi);
                    }
                    if (pss->session.is_established()) {
                        log(LogLevel::SUCCESS, "Session ESTABLISHED with " + pss->virtual_ip);
                    }
                } catch (const std::exception& e) {
                    log(LogLevel::ERROR, "Handshake Error (" + pss->virtual_ip + "): " + e.what());
                    return -1;
                }
            }
            else {
                if (!pss->session.is_established()) return -1;

                if (lws_is_first_fragment(wsi)) pss->rx_buffer.clear();
                pss->rx_buffer.insert(pss->rx_buffer.end(), (uint8_t*)in, (uint8_t*)in + len);

                if (pss->rx_buffer.size() > 65536) return -1;

                if (lws_is_final_fragment(wsi)) {
                    auto key_span = pss->session.get_session_key();
                    std::vector<uint8_t> key(key_span.begin(), key_span.end());

                    app.workers->submit_task({
                        false, // Decrypt
                        std::move(pss->rx_buffer),
                        0, wasp::InnerCommand::IPV4,
                        std::move(key),
                        wsi
                    });

                    pss->rx_buffer = {};
                    lws_cancel_service(app.lws_ctx);
                }
            }
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            // 1. Handshake Priority
            if (!pss->handshake_tx_queue.empty()) {
                auto& msg = pss->handshake_tx_queue.front();
                std::vector<uint8_t> buf(LWS_PRE + msg.size());
                memcpy(buf.data() + LWS_PRE, msg.data(), msg.size());
                lws_write(wsi, buf.data() + LWS_PRE, msg.size(), LWS_WRITE_TEXT);
                pss->handshake_tx_queue.pop();
                if (!pss->handshake_tx_queue.empty()) lws_callback_on_writable(wsi);
                return 0;
            }

            // 2. Encrypted Tunnel Data
            // === FLOW CONTROL FIX ===
            // 2. Encrypted Tunnel Data
            if (!pss->encrypted_tx_queue.empty()) {
                // UNCAP BURST: Send until pipe choked
                while (!pss->encrypted_tx_queue.empty() && !lws_send_pipe_choked(wsi)) {
                    auto& pkt = pss->encrypted_tx_queue.front();

                    if (lws_write(wsi, pkt.data() + LWS_PRE, pkt.size() - LWS_PRE, LWS_WRITE_BINARY) < 0) {
                        return -1;
                    }

                    pss->encrypted_tx_queue.pop();
                }

                if (!pss->encrypted_tx_queue.empty()) {
                    lws_callback_on_writable(wsi);
                }
            }
            break;
        }

        case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
            CryptoResult res;
            while (app.workers->results.try_pop(res)) {
                if (res.wsi == nullptr) continue;

                if (!res.is_encrypted) { // RX Decrypted (from Client) -> Write to TUN
                    app.tun->write(res.data);
                }
                else { // TX Encrypted (to Client) -> Queue for LWS
                    auto* target_pss = (WaspSessionData*)lws_wsi_user(res.wsi);
                    if (target_pss) {
                        target_pss->encrypted_tx_queue.push(std::move(res.data));
                        lws_callback_on_writable(res.wsi);
                    }
                }
            }
            break;
        }

        default: break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "wasp-vpn", callback_wasp, sizeof(WaspSessionData), 65536, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

// ==========================================
// CLI & MAIN
// ==========================================
void print_usage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " run              Start the VPN Server\n"
              << "  " << prog << " add <user> <pw>  Register a new user\n"
              << "  " << prog << " del <user>       Delete a user\n"
              << "  " << prog << " approve <user>   Approve a user\n"
              << "  " << prog << " list             List all users\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    // Init DB
    app.db = std::make_unique<wasp::db::UserManager>("wasp.db");

    if (command == "add") {
        if (argc < 4) { std::cerr << "Missing args.\n"; return 1; }
        if (app.db->add_user(argv[2], argv[3])) std::cout << "User " << argv[2] << " added. (Pending Approval)\n";
        else std::cerr << "User already exists.\n";
        return 0;
    }
    if (command == "del") {
        if (argc < 3) { std::cerr << "Missing username.\n"; return 1; }
        if (app.db->delete_user(argv[2])) std::cout << "User " << argv[2] << " deleted.\n";
        else std::cerr << "User not found.\n";
        return 0;
    }
    if (command == "approve") {
        if (argc < 3) { std::cerr << "Missing username.\n"; return 1; }
        if (app.db->approve_user(argv[2])) std::cout << "User " << argv[2] << " approved.\n";
        else std::cerr << "User not found.\n";
        return 0;
    }
    if (command == "list") {
        auto users = app.db->list_users();
        std::cout << std::left << std::setw(5) << "ID" << std::setw(20) << "Username" << std::setw(10) << "Status" << "\n-----------------------------------\n";
        for (const auto& u : users) {
            std::cout << std::setw(5) << u.id << std::setw(20) << u.username << (u.is_approved ? "[OK]" : "[PENDING]") << "\n";
        }
        return 0;
    }

    if (command == "run") {
        print_banner();
        if (geteuid() != 0) {
            log(LogLevel::ERROR, "Server must run as root.");
            return 1;
        }

        signal(SIGINT, sigint_handler);
        app.sessions.set_is_server(true);

        try {
            app.tun = std::make_unique<wasp::TunDevice>(app.tun_name, true);
            log(LogLevel::SUCCESS, "Interface " + app.tun->get_name() + " initialized.");

            configure_networking();

            unsigned int threads = std::thread::hardware_concurrency();
            app.workers = std::make_unique<WorkerPool>(threads > 0 ? threads : 2);
            log(LogLevel::INFO, "Worker Pool: " + std::to_string(threads) + " threads.");

            struct lws_context_creation_info info = {0};
            info.port = 7681;
            info.protocols = protocols;
            info.gid = -1; info.uid = -1;
            info.count_threads = 1;

            app.lws_ctx = lws_create_context(&info);
            if (!app.lws_ctx) {
                log(LogLevel::ERROR, "LWS Init Failed.");
                return 1;
            }

            app.workers->set_context(app.lws_ctx);

            std::thread tun_thread(tun_reader_thread);

            log(LogLevel::INFO, "Server Running on Port 7681...");
            while (app.running) {
                lws_service(app.lws_ctx, 100);
            }

            if (tun_thread.joinable()) tun_thread.join();
            app.workers->stop();
            lws_context_destroy(app.lws_ctx);
            cleanup_networking();
            log(LogLevel::SUCCESS, "Server Shutdown.");

        } catch (const std::exception& e) {
            log(LogLevel::ERROR, std::string("Fatal Error: ") + e.what());
            return 1;
        }
    }

    return 0;
}