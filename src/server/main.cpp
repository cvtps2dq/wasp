/**
 * WASP Server
 * High-Performance L3 VPN Server
 *
 * Handles multiple WebSocket clients, routes IP traffic,
 * and manages AES-256-GCM encryption tunnels.
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

// Internal Library Includes
#include "db_manager.hpp"
#include "session_manager.hpp" // Manages IP <-> WSI mapping
#include "tun_device.hpp"
#include "wasp_session.hpp"
#include "wasp_utils.hpp"
#include "worker_pool.hpp"

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
    // Traffic logs can be noisy, uncomment to silence
    // if (level == LogLevel::TRAFFIC) return;

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
         Web Augmented Secure Protocol Server v1.1 — cv2 — lumen-rsg                2025
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
    SessionManager sessions;

    struct lws_context* lws_ctx = nullptr;
    std::atomic<bool> running{true};

    // Configuration
    std::string tun_name = "wasp0";
    std::string tun_ip = "10.89.89.1";
    std::string tun_cidr = "24";
    std::unique_ptr<wasp::db::UserManager> db;
};

ServerContext app;

// ==========================================
// Helper: System Commands
// ==========================================
void run_command(const std::string& cmd) {
    log(LogLevel::DEBUG, "CMD: " + cmd);
    int ret = system(cmd.c_str());
    if (ret != 0) log(LogLevel::WARN, "Command returned non-zero exit code.");
}

// ==========================================
// Helper: Get WAN Interface
// ==========================================
std::string get_wan_interface() {
    std::string interface;
    std::array<char, 256> buffer{};

    // Ask the kernel for the route to a public IP (Google DNS)
    // The output is like: "8.8.8.8 via 192.168.1.1 dev enp0s5 src ..."
    FILE* pipe = popen("ip route get 8.8.8.8", "r");
    if (!pipe) return "";

    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string result(buffer.data());
        std::stringstream ss(result);
        std::string word;
        while (ss >> word) {
            if (word == "dev") {
                ss >> interface; // The next word is the interface name
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
    // 1. Assign IP
    run_command("ip addr add " + app.tun_ip + "/" + app.tun_cidr + " dev " + app.tun_name);

    // === FIX 1: LOWER MTU TO 1280 (Safe minimum for VPNs) ===
    run_command("ip link set dev " + app.tun_name + " mtu 1280");

    // 3. Bring Up
    run_command("ip link set " + app.tun_name + " up");

    // 4. IP Forwarding
    run_command("sysctl -w net.ipv4.ip_forward=1");

    // 5. NAT (Masquerading)
    std::string wan_iface = get_wan_interface();
    if (!wan_iface.empty()) {
        log(LogLevel::INFO, "Using '" + wan_iface + "' as WAN interface for NAT.");
        run_command("iptables -t nat -A POSTROUTING -o " + wan_iface + " -j MASQUERADE");
        run_command("iptables -A FORWARD -i " + app.tun_name + " -j ACCEPT");
        run_command("iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT");
    }

    // === FIX 2: DISABLE ALL OFFLOADING (GRO/LRO CAUSES STALLS) ===
    // We disable: tx (transmit checksum), sg (scatter-gather), tso (tcp segmentation),
    // gro (generic receive offload), gso (generic segmentation offload).
    run_command("ethtool -K " + app.tun_name + " tx off sg off tso off gro off gso off > /dev/null 2>&1");

#endif

    log(LogLevel::SUCCESS, "Networking Configured. Listening on " + app.tun_ip);
}

// ==========================================
// TUN Reader Thread (Routing)
// ==========================================
void tun_reader_thread() {
    log(LogLevel::INFO, "TUN Reader thread started.");

    std::vector<uint8_t> buffer(65536);

    while (app.running) {
        // TunDevice::read handles Server Checksum Fixing internally
        ssize_t nread = app.tun->read(buffer);

        if (!app.running) break;
        if (nread <= 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }



        // 1. Packet Parsing
        // We need to look at the Destination IP to know which websocket client gets this packet.
        wasp::ByteSpan packet_span(buffer.data(), nread);
        std::string dst_ip = wasp::utils::get_dst_ip(packet_span);

        if (dst_ip.empty()) continue; // Not IPv4 or malformed

        // === FILTER NOISE ===
        // Ignore Multicast (224.0.0.0 - 239.255.255.255) and Broadcast
        if (dst_ip.length() >= 4 && (
            dst_ip.rfind("224.", 0) == 0 ||
            dst_ip.rfind("239.", 0) == 0 ||
            dst_ip == "255.255.255.255")) {
            // Silently ignore multicast/broadcast to prevent log spam
            continue;
            }

        // 2. Routing Lookup
        struct lws* target_wsi = app.sessions.get_wsi_for_ip(dst_ip);

        if (target_wsi) {
            // log(LogLevel::TRAFFIC, "Routing " + std::to_string(nread) + " bytes -> " + dst_ip);

            auto* pss = (WaspSessionData*)lws_wsi_user(target_wsi);
            if (pss && pss->session.is_established()) {

                // Copy Key (Thread Safety)
                auto key_span = pss->session.get_session_key();
                std::vector<uint8_t> key(key_span.begin(), key_span.end());

                // Copy Data
                std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + nread);

                // Submit to Worker for Encryption
                app.workers->submit_task({
                    true, // is_encrypt
                    std::move(packet),
                    pss->session.get_session_id(),
                    wasp::InnerCommand::IPV4,
                    std::move(key),
                    target_wsi
                });

                // Wake up Main Loop
                lws_cancel_service(app.lws_ctx);
            }
        } else {
            // log(LogLevel::DEBUG, "Drop: No route for " + dst_ip);
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
        // ------------------------------------------------
        // CONNECTION LIFECYCLE
        // ------------------------------------------------
        case LWS_CALLBACK_ESTABLISHED: {
            // Placement New to init session object
            new (pss) WaspSessionData();

            pss->session.set_validator([](const std::string& u, const std::string& p) {
                bool ok = app.db->authenticate(u, p);
                if (ok) log(LogLevel::SUCCESS, "Auth Success: " + u);
                else    log(LogLevel::WARN, "Auth Failed: " + u);
                return ok;
            });

            // Assign Virtual IP
            pss->virtual_ip = app.sessions.register_client(wsi);
            pss->session.set_assigned_ip(pss->virtual_ip);

            // Use WSI pointer as Session ID (or generate random)
            pss->session.set_session_id(reinterpret_cast<uintptr_t>(wsi)); // Truncates on 32bit, but fine for ID

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

        // ------------------------------------------------
        // INCOMING DATA (RX from Client)
        // ------------------------------------------------
        case LWS_CALLBACK_RECEIVE: {
            // A. HANDSHAKE (Text)
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
                    return -1; // Close connection
                }
            }
            // B. DATA TUNNEL (Binary)
            else {
                if (!pss->session.is_established()) return -1;

                // Accumulate Fragmented Frames (LWS feature)
                if (lws_is_first_fragment(wsi)) pss->rx_buffer.clear();
                pss->rx_buffer.insert(pss->rx_buffer.end(), (uint8_t*)in, (uint8_t*)in + len);

                if (pss->rx_buffer.size() > 65536) return -1; // DOS Protection

                if (lws_is_final_fragment(wsi)) {
                    // Packet Complete -> Decrypt via Worker
                    auto key_span = pss->session.get_session_key();
                    std::vector<uint8_t> key(key_span.begin(), key_span.end());

                    app.workers->submit_task({
                        false, // is_encrypt = false (Decrypt)
                        std::move(pss->rx_buffer),
                        0, wasp::InnerCommand::IPV4,
                        std::move(key),
                        wsi
                    });

                    pss->rx_buffer = {}; // Clear for next
                    lws_cancel_service(app.lws_ctx);
                }
            }
            break;
        }

        // ------------------------------------------------
        // OUTGOING DATA (TX to Client)
        // ------------------------------------------------
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
            if (!pss->encrypted_tx_queue.empty()) {
                // Burst send to drain queue efficiently
                int burst = 0;
                while (!pss->encrypted_tx_queue.empty() && burst < 20) {
                    auto& pkt = pss->encrypted_tx_queue.front();

                    if (lws_write(wsi, pkt.data() + LWS_PRE, pkt.size() - LWS_PRE, LWS_WRITE_BINARY) < 0) {
                        return -1;
                    }

                    pss->encrypted_tx_queue.pop();
                    burst++;
                }

                if (!pss->encrypted_tx_queue.empty()) {
                    lws_callback_on_writable(wsi);
                }
            }
            break;
        }

        // ------------------------------------------------
        // WORKER SIGNAL
        // ------------------------------------------------
        case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
            // Poll the Worker Pool for results
            CryptoResult res;
            while (app.workers->results.try_pop(res)) {
                if (res.wsi == nullptr) continue; // Should not happen

                // If it's a Decrypted packet (from Client), write to TUN
                if (!res.is_encrypted) {
                    // log(LogLevel::TRAFFIC, "RX Decrypted " + std::to_string(res.data.size()) + " bytes");
                    app.tun->write(res.data);
                }
                // If it's an Encrypted packet (destined for Client), Queue it
                else {
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
// CLI COMMANDS
// ==========================================
void print_usage(const char* prog) {
    std::cout << "Usage:\n"
              << "  " << prog << " run              Start the VPN Server\n"
              << "  " << prog << " add <user> <pw>  Register a new user\n"
              << "  " << prog << " approve <user>   Approve a user\n"
              << "  " << prog << " list             List all users\n";
}

void cleanup_networking() {
    log(LogLevel::INFO, "Restoring network configuration...");
    std::string wan_iface = get_wan_interface();
    if (!wan_iface.empty()) {
        run_command("iptables -t nat -D POSTROUTING -o " + wan_iface + " -j MASQUERADE");
        run_command("iptables -D FORWARD -i " + app.tun_name + " -j ACCEPT");
        run_command("iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT");
    }
    log(LogLevel::SUCCESS, "Network configuration restored.");
}

// Signal Handler
void sigint_handler(int) {
    log(LogLevel::WARN, "Interrupt received. Shutting down...");
    app.running = false;
    cleanup_networking();
    if (app.lws_ctx) lws_cancel_service(app.lws_ctx);
}

// ==========================================
// MAIN
// ==========================================
int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    // Initialize DB
    app.db = std::make_unique<wasp::db::UserManager>("wasp.db");

    if (command == "add") {
        if (argc < 4) { std::cerr << "Missing args.\n"; return 1; }
        if (app.db->add_user(argv[2], argv[3])) {
            std::cout << "User " << argv[2] << " added. (Pending Approval)\n";
        } else {
            std::cerr << "User already exists.\n";
        }
        return 0;
    }

    if (command == "approve") {
        if (argc < 3) { std::cerr << "Missing username.\n"; return 1; }
        if (app.db->approve_user(argv[2])) {
            std::cout << "User " << argv[2] << " approved.\n";
        } else {
            std::cerr << "User not found.\n";
        }
        return 0;
    }

    if (command == "list") {
        auto users = app.db->list_users();
        std::cout << std::left << std::setw(5) << "ID"
                  << std::setw(20) << "Username"
                  << std::setw(10) << "Status" << "\n";
        std::cout << "-----------------------------------\n";
        for (const auto& u : users) {
            std::cout << std::setw(5) << u.id
                      << std::setw(20) << u.username
                      << (u.is_approved ? "[OK]" : "[PENDING]") << "\n";
        }
        return 0;
    }

    if (command == "del") {
        if (argc < 3) { std::cerr << "Missing username.\n"; return 1; }
        if (app.db->delete_user(argv[2])) {
            std::cout << "User " << argv[2] << " deleted.\n";
        } else {
            std::cerr << "User not found.\n";
        }
        return 0;
    }

    if (command == "run")
    {
        print_banner();

        if (geteuid() != 0) {
            log(LogLevel::ERROR, "Server must run as root to manage TUN interface.");
            return 1;
        }

        // 1. Init Session Manager
        app.sessions.set_is_server(true);

        try {
            // 2. Init TUN Device
            // We request "wasp0". The TunDevice constructor handles creation.
            app.tun = std::make_unique<wasp::TunDevice>(app.tun_name, true);
            log(LogLevel::SUCCESS, "Interface " + app.tun->get_name() + " initialized.");

            // 3. Configure OS Networking (IP, MTU, NAT)
            configure_networking();

            // 4. Init Workers
            unsigned int threads = std::thread::hardware_concurrency();
            app.workers = std::make_unique<WorkerPool>(threads);
            log(LogLevel::INFO, "Worker Pool initialized with " + std::to_string(threads) + " threads.");

            // 5. Init LibWebSockets
            struct lws_context_creation_info info = {0};
            info.port = 7681;
            info.protocols = protocols;
            info.gid = -1; info.uid = -1;
            info.count_threads = 1; // Single threaded Event Loop

            app.lws_ctx = lws_create_context(&info);
            if (!app.lws_ctx) {
                log(LogLevel::ERROR, "LWS Context creation failed.");
                return 1;
            }

            // Link Workers to Context
            app.workers->set_context(app.lws_ctx);

            // 6. Start TUN Reader
            std::thread tun_thread(tun_reader_thread);

            // 7. Event Loop
            log(LogLevel::INFO, "Server Running. Waiting for clients...");
            while (app.running) {
                lws_service(app.lws_ctx, 100);
            }

            // 8. Cleanup
            if (tun_thread.joinable()) tun_thread.join();
            app.workers->stop();
            lws_context_destroy(app.lws_ctx);
            log(LogLevel::SUCCESS, "Server Shutdown.");

        } catch (const std::exception& e) {
            log(LogLevel::ERROR, std::string("Fatal Error: ") + e.what());
            return 1;
        }
    }

    cleanup_networking();
    log(LogLevel::SUCCESS, "Server Shutdown.");
    return 0;
}