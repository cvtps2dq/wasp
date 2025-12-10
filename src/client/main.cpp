/**
 * WASP Client (Sting)
 * High-Performance L3 VPN Client
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
#include <format> // C++20

// Internal Library Includes
#include "worker_pool.hpp"
#include "tun_device.hpp"
#include "wasp_session.hpp"
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

enum class LogLevel { INFO, SUCCESS, WARN, ERROR, DEBUG };

void log(LogLevel level, const std::string& msg) {
    std::cout << Color::BOLD << "[";
    switch (level) {
        case LogLevel::INFO:    std::cout << Color::BLUE   << "INFO"; break;
        case LogLevel::SUCCESS: std::cout << Color::GREEN  << " OK "; break;
        case LogLevel::WARN:    std::cout << Color::YELLOW << "WARN"; break;
        case LogLevel::ERROR:   std::cout << Color::RED    << "ERR "; break;
        case LogLevel::DEBUG:   std::cout << Color::MAGENTA<< "DBUG"; break;
    }
    std::cout << Color::RESET << Color::BOLD << "] " << Color::RESET << msg << std::endl;
}

void print_banner() {
    std::cout << Color::CYAN << R"(
 _       __   _    _____ ____
| |     / /  / \  / ___// __ \
| | /| / /  / _ \ \__ \/ /_/ /
| |/ |/ /  / ___ \___/ / ____/
|__/|__/  /_/   \_\___/_/
    )" << Color::RESET << std::endl;
    std::cout << "   " << Color::BOLD << "WebAugmentedSecureProtocol Client v1.0" << Color::RESET << "\n" << std::endl;
}

// ==========================================
// Global Context
// ==========================================
struct ClientContext {
    std::unique_ptr<wasp::TunDevice> tun;
    std::unique_ptr<WorkerPool> workers;

    wasp::Session session{wasp::Role::CLIENT};
    std::mutex session_mtx;

    std::queue<wasp::ByteBuffer> enc_tx_queue;
    std::queue<wasp::ByteBuffer> handshake_queue;

    struct lws* wsi = nullptr;
    struct lws_context* lws_ctx = nullptr;
    std::atomic<bool> running{true};
    std::atomic<bool> tunnel_ready{false};

    // === ADDED CONFIG FIELDS ===
    std::string config_username;
    std::string config_password;

    std::atomic<bool> fatal_error{false};
};

ClientContext app;

// Signal Handler
void sigint_handler(int) {
    log(LogLevel::WARN, "Interrupt received. Shutting down...");
    app.running = false;
    lws_cancel_service(app.lws_ctx);
}

// ==========================================
// Helper: System Commands
// ==========================================
void run_command(const std::string& cmd) {
    log(LogLevel::DEBUG, "CMD: " + cmd);
    int ret = system(cmd.c_str());
    if (ret != 0) log(LogLevel::WARN, "Command returned non-zero exit code.");
}

// ==========================================
// TUN Reader Thread
// ==========================================
void tun_reader_thread() {
    log(LogLevel::INFO, "TUN Reader thread started.");

    // Pre-allocate buffer for high performance
    std::vector<uint8_t> buffer(65536);

    while (app.running) {
        ssize_t nread = app.tun->read(buffer);

        if (!app.running) break;
        if (nread <= 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            // On fatal read error (e.g. interface down), sleep briefly
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // Only process if tunnel is fully established
        if (app.tunnel_ready) {
            std::lock_guard lock(app.session_mtx);

            // Validate Session
            if (!app.session.is_established()) continue;

            // Prepare Task
            std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + nread);

            // Get Key Copy (Thread Safe)
            auto key_span = app.session.get_session_key();
            std::vector<uint8_t> key(key_span.begin(), key_span.end());

            // Submit to Worker for Encryption
            app.workers->submit_task({
                true, // is_encrypt
                std::move(packet),
                app.session.get_session_id(),
                wasp::InnerCommand::IPV4,
                std::move(key),
                app.wsi
            });

            // Wake up Main Thread to send immediately
            lws_cancel_service(app.lws_ctx);
        }
    }
    log(LogLevel::INFO, "TUN Reader thread stopped.");
}

// ==========================================
// LWS Callback (Main Event Loop)
// ==========================================
static int callback_sting(struct lws *wsi, enum lws_callback_reasons reason,
                          void *user, void *in, size_t len) {

    switch (reason) {
        // ------------------------------------------------
        // CONNECTION LIFECYCLE
        // ------------------------------------------------
    case LWS_CALLBACK_CLIENT_ESTABLISHED: {
        log(LogLevel::SUCCESS, "WebSocket Connected to Server.");
        app.wsi = wsi;

        std::lock_guard lock(app.session_mtx);
        app.session = wasp::Session(wasp::Role::CLIENT);

        // === CHANGED ===
        // Use credentials provided via CLI
        app.session.set_credentials(app.config_username, app.config_password);

        // Initiate Handshake
        try {
            std::string hello = app.session.initiate_handshake();
            wasp::ByteBuffer buf(hello.begin(), hello.end());
            app.handshake_queue.push(std::move(buf));
            lws_callback_on_writable(wsi);
        } catch (const std::exception& e) {
            log(LogLevel::ERROR, std::string("Handshake Init Failed: ") + e.what());
            return -1;
        }
        break;
    }

        case LWS_CALLBACK_CLIENT_CLOSED:
            log(LogLevel::WARN, "Connection Closed.");
            app.wsi = nullptr;
            app.tunnel_ready = false;
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            log(LogLevel::ERROR, "Connection Error.");
            app.wsi = nullptr;
            app.tunnel_ready = false;
            break;

        // ------------------------------------------------
        // INCOMING DATA (RX)
        // ------------------------------------------------
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            // A. HANDSHAKE (Text Frames)
            if (!lws_frame_is_binary(wsi)) {
                std::string msg((char*)in, len);
                std::lock_guard lock(app.session_mtx);
                try {
                    auto reply = app.session.handle_handshake_msg(msg);

                    if (reply) {
                        // Queue response (Auth, etc.)
                        wasp::ByteBuffer buf(reply->begin(), reply->end());
                        app.handshake_queue.push(std::move(buf));
                        lws_callback_on_writable(wsi);
                    }

                    // Check if Handshake Just Finished
                    if (app.session.is_established() && !app.tunnel_ready) {
                        app.tunnel_ready = true;
                        std::string ip = app.session.get_assigned_ip();
                        log(LogLevel::SUCCESS, "Tunnel ESTABLISHED! Assigned IP: " + ip);

                        // Configure OS Interface
                        #if defined(__APPLE__)
                            run_command("sudo ifconfig " + app.tun->get_name() + " " + ip + " 10.89.89.1 up");
                            run_command("sudo route add -net 10.89.89.0/24 -interface " + app.tun->get_name());
                        #elif defined(__linux__)
                            run_command("sudo ip addr add " + ip + "/24 dev " + app.tun->get_name());
                            run_command("sudo ip link set " + app.tun->get_name() + " up");
                        #endif
                    }
                }
                catch (const wasp::AuthError& e) {
                    log(LogLevel::ERROR, std::string(Color::RED) + "FATAL AUTH ERROR: " + e.what());
                    app.fatal_error = true; // Signal main loop to stop
                    return -1; // Close connection
                }
                catch (const std::exception& e) {
                    log(LogLevel::ERROR, std::string("Handshake Error: ") + e.what());
                    return -1;
                }
            }
            // B. DATA TUNNEL (Binary Frames)
            else {
                if (!app.tunnel_ready) return 0;

                // Optimization: Direct Decrypt on Main Thread (Lowest Latency)
                // Skip the worker pool for RX to avoid context switching overhead for return traffic.
                try {
                    // 1. Zero-Copy Span
                    wasp::ByteSpan data_span((uint8_t*)in, len);

                    // 2. Decrypt
                    // Note: session_mtx needed if key rotation happens dynamically
                    // For perf, we might assume keys are stable during Established state
                    // TODO
                    auto pkt = wasp::parse_packet(data_span, app.session.get_session_key());

                    // 3. Write to TUN
                    if (!pkt.ip_data.empty()) {
                        app.tun->write(pkt.ip_data);
                    }
                } catch (const std::exception& e) {
                    // log(LogLevel::DEBUG, std::string("Drop Bad Packet: ") + e.what());
                }
            }
            break;
        }

        // ------------------------------------------------
        // OUTGOING DATA (TX)
        // ------------------------------------------------
        case LWS_CALLBACK_CLIENT_WRITEABLE: {

            // 1. Handshake Priority
            if (!app.handshake_queue.empty()) {
                auto& msg = app.handshake_queue.front();
                std::vector<uint8_t> buf(LWS_PRE + msg.size());
                memcpy(buf.data() + LWS_PRE, msg.data(), msg.size());

                if (lws_write(wsi, buf.data() + LWS_PRE, msg.size(), LWS_WRITE_TEXT) < 0) return -1;

                app.handshake_queue.pop();
                if (!app.handshake_queue.empty()) lws_callback_on_writable(wsi);
                return 0;
            }

            // 2. Encrypted Tunnel Data
            // We pull from the thread-safe result queue of the WorkerPool
            CryptoResult res;
            // Drain up to 10 packets per loop to prevent starvation but allow read interleaving
            int burst = 0;
            while (burst < 20 && app.workers->results.try_pop(res)) {
                if (res.is_encrypted) {
                    // Send to WebSocket
                    // Note: build_data_packet already added LWS_PRE padding
                    if (lws_write(wsi, res.data.data() + LWS_PRE, res.data.size() - LWS_PRE, LWS_WRITE_BINARY) < 0) {
                        return -1;
                    }
                    burst++;
                }
            }

            // If we hit the burst limit or queue still has items, request more time
            if (!app.workers->results.empty()) {
                lws_callback_on_writable(wsi);
            }
            break;
        }

        // ------------------------------------------------
        // WORKER SIGNAL
        // ------------------------------------------------
        case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
            // The Worker thread woke us up because encryption is done.
            // Request a Write callback to drain the queue.
            if (app.wsi) {
                lws_callback_on_writable(app.wsi);
            }
            break;
        }

        default: break;
    }
    return 0;
}

// LWS Protocols
static struct lws_protocols protocols[] = {
    { "wasp-vpn", callback_sting, 0, 65536, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

// ==========================================
// MAIN
// ==========================================
int main(int argc, char** argv) {
    print_banner();

    if (geteuid() != 0) {
        log(LogLevel::ERROR, "Sting requires root privileges to manage the TUN interface.");
        return 1;
    }

    // === CHANGED ARGUMENT PARSING ===
    if (argc < 4) {
        std::cerr << Color::YELLOW << "Usage: ./sting <server_ip> <username> <password>" << Color::RESET << std::endl;
        return 1;
    }

    std::string server_address = argv[1];
    app.config_username = argv[2];
    app.config_password = argv[3];

    log(LogLevel::INFO, "Target Server: " + server_address);
    log(LogLevel::INFO, "User: " + app.config_username);

    // 3. Signals
    signal(SIGINT, sigint_handler);

    try {
        // 4. Init TUN
        app.tun = std::make_unique<wasp::TunDevice>("wasp_cli", false); // Client mode
        log(LogLevel::SUCCESS, "Interface " + app.tun->get_name() + " initialized.");

        // 5. Init Workers (Use Hardware Concurrency)
        unsigned int threads = std::thread::hardware_concurrency();
        app.workers = std::make_unique<WorkerPool>(threads);
        log(LogLevel::INFO, "Worker Pool initialized with " + std::to_string(threads) + " threads.");

        // 6. Init LibWebSockets
        struct lws_context_creation_info info = {0};
        info.port = CONTEXT_PORT_NO_LISTEN;
        info.protocols = protocols;
        info.gid = -1;
        info.uid = -1;
        // CRITICAL: Keep main loop single-threaded for LWS simplicity
        info.count_threads = 1;

        app.lws_ctx = lws_create_context(&info);
        if (!app.lws_ctx) {
            log(LogLevel::ERROR, "LWS Context creation failed.");
            return 1;
        }

        // Link Workers to LWS Context for Wake-up signaling
        app.workers->set_context(app.lws_ctx);

        // 7. Connect Info
        struct lws_client_connect_info ccinfo = {0};
        ccinfo.context = app.lws_ctx;
        ccinfo.address = server_address.c_str();
        ccinfo.port = 7681;
        ccinfo.path = "/";
        ccinfo.protocol = protocols[0].name;
        ccinfo.pwsi = &app.wsi;

        log(LogLevel::INFO, "Connecting...");
        lws_client_connect_via_info(&ccinfo);

        // 8. Start TUN Reader
        std::thread tun_thread(tun_reader_thread);

        // 9. Main Loop
        while (app.running) {
            lws_service(app.lws_ctx, 100);

            if (!app.wsi && app.running) {
                // === CHECK FATAL ERROR ===
                if (app.fatal_error) {
                    log(LogLevel::ERROR, "Fatal error occurred. Exiting.");
                    break; // Exit the loop
                }

                std::this_thread::sleep_for(std::chrono::seconds(1));
                log(LogLevel::INFO, "Reconnecting...");
                lws_client_connect_via_info(&ccinfo);
            }
        }

        // 10. Cleanup
        if (tun_thread.joinable()) tun_thread.join();
        app.workers->stop();
        lws_context_destroy(app.lws_ctx);
        log(LogLevel::SUCCESS, "Shutdown complete.");

    } catch (const std::exception& e) {
        log(LogLevel::ERROR, std::string("Fatal Error: ") + e.what());
        return 1;
    }

    return 0;
}