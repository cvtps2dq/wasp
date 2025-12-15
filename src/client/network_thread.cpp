/**
 * WASP Client (Sting) Network Backend
 * v1.4 - Debugging Connection Failure
 */

#include "network_thread.hpp"

// Standard Includes
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <queue>
#include <string>
#include <cstring>
#include <csignal>
#include <mutex>
#include <iomanip>
#include <format>
#include <array>
#include <cstdio>

// WASP Library Includes
#include "wasp_session.hpp"
#include "worker_pool.hpp"
#include "tun_device.hpp"
#include "wasp_utils.hpp"

namespace {

AppState* g_state = nullptr;

// Helper Type for the Handshake Queue
using HandshakeQueue = std::queue<wasp::ByteBuffer>;

void log_dual(LogLevel level, const std::string& msg) {
    if (level == LogLevel::ERROR) std::cerr << "[NET-ERR] " << msg << std::endl;
    else if (level == LogLevel::WARN) std::cout << "[NET-WARN] " << msg << std::endl;
    else if (level == LogLevel::DEBUG) std::cout << "[NET-DBG] " << msg << std::endl;
    else std::cout << "[NET-INFO] " << msg << std::endl;

    if (g_state) g_state->log_queue.push({level, msg});
}

void run_command(const std::string& cmd) {
    system(cmd.c_str());
}

std::string get_default_gateway() {
    std::string gateway;
    std::array<char, 128> buffer;
    FILE* pipe = popen("netstat -rn | grep default", "r");
    if (!pipe) return "";
    if (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string result(buffer.data());
        std::stringstream ss(result);
        std::string default_keyword, gateway_ip;
        ss >> default_keyword >> gateway_ip;
        gateway = gateway_ip;
    }
    pclose(pipe);
    return gateway;
}

void cleanup_routing() {
    if (g_state && g_state->tunnel_ready) {
        log_dual(LogLevel::INFO, "Restoring network routes...");
        #if defined(__APPLE__)
            run_command("sudo route delete -net 0.0.0.0/1 >/dev/null 2>&1");
            run_command("sudo route delete -net 128.0.0.0/1 >/dev/null 2>&1");
            if (!g_state->server_resolved_ip.empty()) {
                run_command("sudo route delete " + g_state->server_resolved_ip + " >/dev/null 2>&1");
            }
        #elif defined(__linux__)
            run_command("sudo ip route del 0.0.0.0/1 >/dev/null 2>&1");
            run_command("sudo ip route del 128.0.0.0/1 >/dev/null 2>&1");
            if (!g_state->server_resolved_ip.empty()) {
                run_command("sudo ip route del " + g_state->server_resolved_ip + " >/dev/null 2>&1");
            }
        #endif
        g_state->tunnel_ready = false;
    }
}

    // --- TUN Reader Thread ---
    void tun_reader_loop() {
    log_dual(LogLevel::INFO, "TUN Thread: Started.");
    std::vector<uint8_t> buffer(65536);

    while (g_state && !g_state->exit_requested) {
        if (!g_state->tunnel_ready) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        // === FLOW CONTROL (BACKPRESSURE) ===
        // If we have too many packets waiting to be sent, stop reading from TUN.
        // This prevents memory ballooning and allows the network to catch up.
        // 500 packets * ~1400 bytes = ~700KB buffered.
        if (g_state->workers->results.size() > 500) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        // ===================================

        ssize_t nread = g_state->tun->read(buffer);
        if (g_state->exit_requested) break;

        if (nread <= 0) {
            if (nread == -1 && errno == EBADF) break;
            if (errno == EAGAIN || errno == EINTR) continue;
            continue;
        }

        if (g_state->tunnel_ready && g_state->session.is_established()) {
            std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + nread);
            auto key_span = g_state->session.get_session_key();
            std::vector<uint8_t> key(key_span.begin(), key_span.end());

            g_state->workers->submit_task({
                true, std::move(packet), g_state->session.get_session_id(),
                wasp::InnerCommand::IPV4, std::move(key), g_state->wsi
            });

            // Note: bytes_sent tracks encrypted writes, maybe track raw reads here for stats?
            if(g_state->lws_ctx) lws_cancel_service(g_state->lws_ctx);
        }
    }
    log_dual(LogLevel::INFO, "TUN Thread: Exiting.");
}

// --- LWS Callback ---
int callback_sting(struct lws *wsi, enum lws_callback_reasons reason,
                          void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            log_dual(LogLevel::SUCCESS, "LWS: Connected.");
            g_state->wsi = wsi;
            g_state->connection_status = AppState::Status::CONNECTED;
            g_state->fatal_auth_error = false;
            g_state->retry_count = 0;

            char ip_buf[64] = {0};
            lws_get_peer_simple(wsi, ip_buf, sizeof(ip_buf));
            g_state->server_resolved_ip = ip_buf;

            g_state->session = wasp::Session(wasp::Role::CLIENT);
            g_state->session.set_credentials(g_state->username, g_state->password);

            try {
                std::string hello = g_state->session.initiate_handshake();
                wasp::ByteBuffer buf(hello.begin(), hello.end());

                auto* q = new HandshakeQueue();
                lws_set_opaque_user_data(wsi, q);
                q->push(std::move(buf));

                lws_callback_on_writable(wsi);
            } catch (const std::exception& e) {
                log_dual(LogLevel::ERROR, std::string("Handshake Init Error: ") + e.what());
                return -1;
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CLOSED:
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            // Log exact error if provided
            if (in && len > 0) {
                std::string err((char*)in, len);
                log_dual(LogLevel::ERROR, "LWS Error Detail: " + err);
            }

            auto* q = static_cast<HandshakeQueue*>(lws_get_opaque_user_data(wsi));
            if (q) {
                delete q;
                lws_set_opaque_user_data(wsi, nullptr);
            }

            g_state->wsi = nullptr;
            g_state->tunnel_ready = false;
            cleanup_routing();

            if (g_state->maintain_connection && !g_state->fatal_auth_error) {
                g_state->connection_status = AppState::Status::CONNECTING;
                g_state->retry_count++;
                int delay = (g_state->retry_count > 3) ? 5 : 1;
                g_state->next_reconnect_time = std::chrono::steady_clock::now() + std::chrono::seconds(delay);
                log_dual(LogLevel::WARN, "Connection lost/failed. Retrying in " + std::to_string(delay) + "s...");
            } else {
                if (g_state->connection_status != AppState::Status::FAILED) {
                    g_state->connection_status = AppState::Status::DISCONNECTED;
                }
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            if (!lws_frame_is_binary(wsi)) {
                std::string msg((char*)in, len);
                try {
                    auto reply = g_state->session.handle_handshake_msg(msg);
                    if (reply) {
                        wasp::ByteBuffer buf(reply->begin(), reply->end());
                        auto* q = static_cast<HandshakeQueue*>(lws_get_opaque_user_data(wsi));
                        if(q) q->push(std::move(buf));
                        lws_callback_on_writable(wsi);
                    }

                    if (g_state->session.is_established() && !g_state->tunnel_ready) {
                        g_state->tunnel_ready = true;
                        g_state->assigned_ip = g_state->session.get_assigned_ip();
                        log_dual(LogLevel::SUCCESS, "VPN Active! Virtual IP: " + g_state->assigned_ip);

                        g_state->original_gateway_ip = get_default_gateway();
                        std::string vpn_gw = "10.89.89.1";

                        log_dual(LogLevel::INFO, "VPN Server IP: " + g_state->server_resolved_ip);

                        #if defined(__APPLE__)
                        // === FIX 3: SET MTU 1280 ===
                        run_command("sudo ifconfig " + g_state->tun->get_name() + " mtu 1280");
                        // ===========================

                        run_command("sudo ifconfig " + g_state->tun->get_name() + " " + g_state->assigned_ip + " " + vpn_gw + " up");
                        run_command("sudo route add " + g_state->server_resolved_ip + " " + g_state->original_gateway_ip + " >/dev/null 2>&1");
                        run_command("sudo route add -net 0.0.0.0/1 " + vpn_gw + " >/dev/null 2>&1");
                        run_command("sudo route add -net 128.0.0.0/1 " + vpn_gw + " >/dev/null 2>&1");

                        #elif defined(__linux__)
                        // === FIX 3: SET MTU 1280 ===
                        run_command("sudo ip link set dev " + g_state->tun->get_name() + " mtu 1280");
                        // ===========================

                        run_command("sudo ip addr add " + g_state->assigned_ip + "/24 dev " + g_state->tun->get_name());
                        run_command("sudo ip link set " + g_state->tun->get_name() + " up");
                        run_command("sudo ip route add " + g_state->server_resolved_ip + " via " + g_state->original_gateway_ip);
                        run_command("sudo ip route add 0.0.0.0/1 via " + vpn_gw);
                        run_command("sudo ip route add 128.0.0.0/1 via " + vpn_gw);
                        #endif
                        g_state->connection_status = AppState::Status::CONNECTED;
                    }
                } catch (const wasp::AuthError& e) {
                    log_dual(LogLevel::ERROR, std::string("Auth Failed: ") + e.what());
                    g_state->fatal_auth_error = true;
                    g_state->connection_status = AppState::Status::FAILED;
                    return -1;
                } catch (const std::exception& e) { return -1; }
            } else {
                if (!g_state->tunnel_ready) return 0;
                wasp::ByteSpan data_span((uint8_t*)in, len);
                try {
                    auto pkt = wasp::parse_packet(data_span, g_state->session.get_session_key());
                    if (!pkt.ip_data.empty()) {
                        g_state->tun->write(pkt.ip_data);
                        g_state->bytes_received += pkt.ip_data.size();
                    }
                } catch (...) {}
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            auto* q = static_cast<HandshakeQueue*>(lws_get_opaque_user_data(wsi));

            // 1. Handshake Priority (unchanged)
            if (q && !q->empty()) {
                auto& msg = q->front();
                std::vector<uint8_t> buf(LWS_PRE + msg.size());
                memcpy(buf.data() + LWS_PRE, msg.data(), msg.size());
                lws_write(wsi, buf.data() + LWS_PRE, msg.size(), LWS_WRITE_TEXT);
                q->pop();
                if (!q->empty()) lws_callback_on_writable(wsi);
                return 0;
            }

            // 2. Encrypted Data with Flow Control
            CryptoResult res;

            // Keep sending as long as we have data AND the socket isn't full
            while (!lws_send_pipe_choked(wsi) && g_state->workers->results.try_pop(res)) {
                if (res.is_encrypted) {
                    int n = lws_write(wsi, res.data.data() + LWS_PRE, res.data.size() - LWS_PRE, LWS_WRITE_BINARY);

                    if (n < 0) {
                        log_dual(LogLevel::ERROR, "Write failed - closing connection");
                        return -1; // Socket dead
                    }

                    g_state->bytes_sent += (res.data.size() - LWS_PRE);
                }
            }

            // If we still have data but stopped because of choke or burst limit, ask for callback again
            if (!g_state->workers->results.empty()) {
                lws_callback_on_writable(wsi);
            }
            break;
        }

        case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
            if (g_state->wsi) lws_callback_on_writable(g_state->wsi);
            break;

        default: break;
    }
    return 0;
}

static struct lws_protocols protocols[] = {
    { "wasp-vpn", callback_sting, 0, 65536, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

} // namespace

// ==========================================
// ENTRY POINT
// ==========================================
void network_thread_main(AppState* state) {
    g_state = state;

    // === DEBUG: Enable LWS Logging to console ===
    // lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

    log_dual(LogLevel::INFO, "Network Backend: Initializing...");

    try {
        g_state->tun = std::make_unique<wasp::TunDevice>("wasp_cli", false);
    } catch (const std::exception& e) {
        log_dual(LogLevel::ERROR, std::string("TUN Init Failed: ") + e.what());
        g_state->connection_status = AppState::Status::FAILED;
        return;
    }

    g_state->workers = std::make_unique<WorkerPool>(2);

    struct lws_context_creation_info info = {0};
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1; info.uid = -1;
    info.count_threads = 1;

    g_state->lws_ctx = lws_create_context(&info);
    if (!g_state->lws_ctx) {
        log_dual(LogLevel::ERROR, "LWS Init Failed.");
        g_state->connection_status = AppState::Status::FAILED;
        return;
    }
    g_state->workers->set_context(g_state->lws_ctx);

    std::thread tun_thread;
    if (g_state->tun) tun_thread = std::thread(tun_reader_loop);

    log_dual(LogLevel::SUCCESS, "Network Backend: Ready.");

    while (!g_state->exit_requested) {

        // A. DISCONNECT
        if (g_state->disconnect_request) {
            log_dual(LogLevel::INFO, "Processing DISCONNECT request...");
            g_state->disconnect_request = false;
            g_state->maintain_connection = false;
            if (g_state->wsi) lws_set_timeout(g_state->wsi, PENDING_TIMEOUT_USER_REASON_BASE, 1);
            cleanup_routing();
            g_state->connection_status = AppState::Status::DISCONNECTED;
        }

        // B. CONNECT
        if (g_state->connect_request) {
            log_dual(LogLevel::INFO, "Processing CONNECT request...");
            g_state->connect_request = false;

            if (g_state->lws_ctx) {
                g_state->maintain_connection = true;
                g_state->connection_status = AppState::Status::CONNECTING;
                g_state->fatal_auth_error = false;
                g_state->retry_count = 0;
                g_state->next_reconnect_time = std::chrono::steady_clock::now();
            }
        }

        // C. Connection Manager
        if (g_state->maintain_connection && !g_state->wsi && !g_state->fatal_auth_error && g_state->lws_ctx) {
            auto now = std::chrono::steady_clock::now();

            if (now >= g_state->next_reconnect_time) {
                if (g_state->retry_count > 0) {
                    log_dual(LogLevel::DEBUG, "Auto-reconnecting...");
                }

                struct lws_client_connect_info ccinfo = {0};
                ccinfo.context = g_state->lws_ctx;

                // Copy connection strings to local stack for thread safety
                std::string raw_input = g_state->server_host;
                std::string final_host;
                int final_port;

                size_t colon_pos = raw_input.find(':');
                if (colon_pos != std::string::npos) {
                    final_host = raw_input.substr(0, colon_pos);
                    try {
                        final_port = std::stoi(raw_input.substr(colon_pos + 1));
                    } catch(...) {
                        final_port = g_state->server_port;
                    }
                } else {
                    final_host = raw_input;
                    final_port = g_state->server_port;
                }

                ccinfo.address = final_host.c_str();
                ccinfo.port = final_port;
                ccinfo.path = "/";

                // Explicitly set Host Header
                ccinfo.host = ccinfo.address;
                ccinfo.origin = ccinfo.address;

                ccinfo.protocol = protocols[0].name;
                ccinfo.pwsi = &g_state->wsi;
                ccinfo.opaque_user_data = nullptr; // Clean initialization

                // Standard defaults
                ccinfo.ssl_connection = 0;
                ccinfo.ietf_version_or_minus_one = -1;

                log_dual(LogLevel::DEBUG, "Dialing " + final_host + ":" + std::to_string(final_port) + "...");

                if (!lws_client_connect_via_info(&ccinfo)) {
                    log_dual(LogLevel::ERROR, "LWS Connect Call Failed (Immediate).");
                    g_state->next_reconnect_time = now + std::chrono::seconds(2);
                } else {
                    g_state->next_reconnect_time = now + std::chrono::seconds(5);
                }
            }
        }

        if (g_state->lws_ctx) {
            lws_service(g_state->lws_ctx, 50);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    log_dual(LogLevel::INFO, "Backend shutting down...");
    g_state->maintain_connection = false;
    cleanup_routing();
    if (g_state->tun) g_state->tun->close_fd();
    if (tun_thread.joinable()) tun_thread.join();
    g_state->workers->stop();
    if (g_state->lws_ctx) lws_context_destroy(g_state->lws_ctx);
    log_dual(LogLevel::SUCCESS, "Backend Stopped.");
}