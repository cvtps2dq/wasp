#include <arpa/inet.h>
#include <atomic>
#include <csignal>
#include <fcntl.h>
#include <format>
#include <iomanip>
#include <iostream>
#include <libwebsockets.h>
#include <netinet/ip.h>
#include <new>
#include <queue>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "wasp_utils.hpp"

#if defined(__linux__)
#include <linux/if.h>
#include <linux/if_tun.h>
#elif defined(__APPLE__)
#include <net/if_utun.h>
#include <netinet/in.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#endif

#include "session_manager.hpp"
#include "wasp_crypto.hpp"
#include "wasp_defs.hpp"
#include "wasp_session.hpp"
#include "worker_pool.hpp"

struct WaspSessionData {
  wasp::Session session;
  wasp::ByteBuffer rx_buffer;
  std::queue<wasp::ByteBuffer> handshake_tx_queue;
  std::queue<wasp::ByteBuffer> encrypted_tx_queue;
  std::string virtual_ip;
  std::string tun_iface_name;
  explicit WaspSessionData(const wasp::Role role) : session(role) {}
};

volatile int force_exit = 0;
void signal_handler(int) { force_exit = 1; }

struct AppContext {
  int tun_fd = -1;
  SessionManager session_manager;
  std::unique_ptr<WorkerPool> worker_pool;
  struct lws_context *lws_ctx = nullptr;
  std::atomic<bool> running{true};
  std::atomic<struct lws *> client_wsi{nullptr};
};
AppContext app;


void run_command(const std::string &command) {
  std::cout << "[CMD] Running: " << command << std::endl;
  if (const int ret = system(command.c_str()); ret != 0)
    std::cerr << "[CMD] Warning: Exit code " << ret << std::endl;
}

void print_hex(const std::string &label, const wasp::ByteSpan data) {
  std::cout << label << " (first 24 bytes): ";
  for (size_t i = 0; i < std::min(static_cast<size_t>(24), data.size()); ++i) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(data[i]) << " ";
  }
  std::cout << std::dec << std::endl;
}

#if defined(__APPLE__)
int tun_alloc(char *dev_name) {
  const int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd < 0)
    return -1;
  struct ctl_info info{};
  memset(&info, 0, sizeof(info));
  strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
  if (ioctl(fd, CTLIOCGINFO, &info) == -1) {
    close(fd);
    return -1;
  }
  struct sockaddr_ctl sc{};
  memset(&sc, 0, sizeof(sc));
  sc.sc_len = sizeof(sc);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = AF_SYS_CONTROL;
  sc.sc_id = info.ctl_id;
  sc.sc_unit = 0;
  if (connect(fd, reinterpret_cast<struct sockaddr *>(&sc), sizeof(sc)) == -1) {
    close(fd);
    return -1;
  }
  char name[256];
  socklen_t len = sizeof(name);
  if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &len) == -1) {
    strcpy(dev_name, "utun?");
  } else {
    strcpy(dev_name, name);
  }
  return fd;
}
ssize_t tun_read(int fd, void* buf, size_t capacity) {
    // We need 4 bytes headroom for the OS header
    if (capacity < 4) return -1;

    ssize_t nread;
    do {
        nread = read(fd, buf, capacity);
    } while (nread < 0 && errno == EINTR);

    if (nread <= 4) return -1; // Garbage or empty

    // Hardening: memmove is safer than memcpy for overlapping regions,
    // and modern CPUs optimize it to vector instructions (AVX/SSE).
    uint8_t* ptr = static_cast<uint8_t*>(buf);
    std::memmove(ptr, ptr + 4, nread - 4);

    return nread - 4; // Return actual IP payload size
}
ssize_t tun_write(int fd, const void* buf, size_t count) {
    // Standard UTUN expects Network Byte Order (Big Endian)
    uint32_t af = htonl(AF_INET);

    std::vector<uint8_t> p(4 + count);
    memcpy(p.data(), &af, 4);
    memcpy(p.data() + 4, buf, count);

    return write(fd, p.data(), p.size());
}

#elif defined(__linux__)

int tun_alloc(char *dev_name) {
    struct ifreq ifr;
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return -1;

    memset(&ifr, 0, sizeof(ifr));
    // IFF_NO_PI is crucial here. It tells Linux "Don't send/expect protocol info headers"
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev_name) strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) { close(fd); return -1; }
    strcpy(dev_name, ifr.ifr_name);
    return fd;
}

// Linux: Read/Write RAW IP data directly.
ssize_t tun_read(int fd, void* buf, size_t capacity) {
    ssize_t nread;
    do {
        nread = read(fd, buf, capacity);
    } while (nread < 0 && errno == EINTR); // Retry if interrupted by signal
    return nread;
}

ssize_t tun_write(int fd, const void* buf, size_t count) {
    return write(fd, buf, count);
}

#endif



std::string get_dst_ip(wasp::ByteSpan packet) {
  if (packet.size() < sizeof(struct ip))
    return "";
  const auto *ip_header = reinterpret_cast<const struct ip *>(packet.data());
  if (ip_header->ip_v != 4)
    return "";
  char buffer[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(ip_header->ip_dst), buffer, INET_ADDRSTRLEN);
  return {buffer};
}

constexpr size_t MAX_PACKET_SIZE = 65536;

void tun_reader_thread() {
    std::cout << "[TUN] High-Performance Reader thread started.\n";

    // Hardening: Pre-allocate session key buffer to reuse memory logic if possible
    // (Though for thread safety with std::move, we re-alloc inside loop)

    while (app.running) {
        // 1. Allocation Strategy for High Perf:
        // In a true 10Gbps DPDK app, we would pop this from a pre-allocated Ring Buffer.
        // For standard sockets, std::vector default construction is fast, but we optimize
        // by reserving immediately to avoid re-allocs during the read.
        wasp::ByteBuffer packet_data;
        packet_data.resize(MAX_PACKET_SIZE);

        // 2. Direct Read (Zero Copy from Kernel to User Vector)
        // Pass vector's internal pointer directly to syscall
        ssize_t nread = tun_read(app.tun_fd, packet_data.data(), MAX_PACKET_SIZE);

        // 3. Error Hardening
        if (nread <= 0) {
            if (nread < 0) {
                // Ignore temporary errors, break on fatal ones
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    std::this_thread::yield(); // Prevent 100% CPU burn on non-blocking
                    continue;
                }
                if (errno == EBADF) break; // File descriptor closed (shutdown)
                perror("[TUN] Read Error");
            }
            continue;
        }

        // 4. Shrink vector to fit (Cheap integer op, no reallocation)
        packet_data.resize(nread);

        // 5. Packet Validation (Sanity Check)
        // Discard packet if too small for IPv4 header (20 bytes)
        if (nread < 20) continue;

        // Discard non-IPv4 packets immediately (We only support IPv4)
        uint8_t ip_version = packet_data[0] >> 4;
        if (ip_version != 4) continue;

        // 6. Checksum Fix (In-Place / No Copy)
        // Critical for Linux Servers due to offloading.
        if (app.session_manager.is_server()) {
            wasp::utils::fix_packet_checksums(packet_data.data(), nread);
            //wasp::utils::print_packet("SRV-BSD", packet_data.data(), nread);
        }

        // 7. Routing & Session Lookup
        struct lws* target_wsi = nullptr;
        std::vector<uint8_t> key_copy;
        uint32_t session_id = 0;

        if (app.session_manager.is_server()) {
            // Optimization: Parse IP from raw bytes manually to avoid string allocations
            // Struct ip is at packet_data.data()
            std::string dst_ip = get_dst_ip(packet_data);

            // Critical Section: Fast Lock
            // We assume get_wsi_for_ip handles the lock internally and quickly.
            target_wsi = app.session_manager.get_wsi_for_ip(dst_ip);

            if (!target_wsi) {
                // Drop packet silently to avoid log spam on scanning
                continue;
            }
        } else {
            // Client Mode: Atomic Load
            target_wsi = app.client_wsi.load(std::memory_order_relaxed);
        }

        // 8. Dispatch to Worker (Move Semantics)
        if (target_wsi) {
            // Thread-Safety Hardening:
            // We must retrieve the key *now* while we know the session is valid.
            // Accessing pss->session_key inside the worker thread is dangerous if
            // the connection closes and memory is freed.
            // We COPY the 32-byte key here. It's small (AVX copy is 1 cycle).

            auto* pss = (WaspSessionData*)lws_wsi_user(target_wsi);
            if (pss && pss->session.is_established()) {
                // Get Key
                auto k = pss->session.get_session_key();
                key_copy.assign(k.begin(), k.end());
                session_id = pss->session.get_session_id();

                // Submit
                app.worker_pool->submit_task({
                    true,                       // is_encrypt
                    std::move(packet_data),     // Move the vector (No Data Copy)
                    session_id,
                    wasp::InnerCommand::IPV4,
                    std::move(key_copy),        // Move the key
                    target_wsi
                });
            }
        }
    }
    std::cout << "[TUN] Reader thread finished.\n";
}

// ... (Callback - Unchanged) ...
static int callback_wasp(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len) {
  auto *pss = static_cast<WaspSessionData *>(user);
  switch (reason) {
  case LWS_CALLBACK_ESTABLISHED:
    new (pss) WaspSessionData(wasp::Role::SERVER);
    pss->virtual_ip = app.session_manager.register_client(wsi);
    pss->session.set_assigned_ip(pss->virtual_ip);
    pss->session.set_session_id(reinterpret_cast<uintptr_t>(wsi));
    break;
  case LWS_CALLBACK_CLOSED:
    app.session_manager.unregister_client(wsi);
    if (pss)
      pss->~WaspSessionData();
    break;
  case LWS_CALLBACK_CLIENT_ESTABLISHED: {
    new (pss) WaspSessionData(wasp::Role::CLIENT);
    app.client_wsi = wsi;
    if (void *opaque = lws_get_opaque_user_data(wsi))
      pss->tun_iface_name = static_cast<char *>(opaque);
    try {
      auto hello = pss->session.initiate_handshake();
      pss->handshake_tx_queue.emplace(hello.begin(), hello.end());
      lws_callback_on_writable(wsi);
    } catch (const std::exception &) {
      return -1;
    }
    break;
  }
  case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
  case LWS_CALLBACK_CLIENT_CLOSED:
    if (pss)
      pss->~WaspSessionData();
    app.client_wsi = nullptr;
    force_exit = 1;
    break;
  case LWS_CALLBACK_RECEIVE:
  case LWS_CALLBACK_CLIENT_RECEIVE: {
    if (!pss->session.is_established()) {
      if (lws_frame_is_binary(wsi))
        return -1;
      const std::string_view msg(static_cast<char *>(in), len);
      try {
        if (auto reply = pss->session.handle_handshake_msg(msg)) {
          pss->handshake_tx_queue.emplace(reply->begin(), reply->end());
          lws_callback_on_writable(wsi);
        } else if (pss->session.is_established() &&
                   pss->session.get_role() == wasp::Role::CLIENT) {
          pss->virtual_ip = pss->session.get_assigned_ip();
          std::cout << "\n[WASP] Handshake Complete! Tunnel ESTABLISHED. IP: "
                    << pss->virtual_ip << "\n";
            std::string cmd = std::format("sudo ifconfig {} {} 10.89.89.1 up", pss->tun_iface_name, pss->virtual_ip);
            run_command(cmd);
            std::cout << "\n[WASP] Ready. Ping 10.89.89.1\n" << std::endl;
        }
      } catch (const std::exception &) {
        return -1;
      }
    } else {
      if (!lws_frame_is_binary(wsi))
        return -1;

      // 1. Accumulate Data
      if (lws_is_first_fragment(wsi))
        pss->rx_buffer.clear();
      pss->rx_buffer.insert(pss->rx_buffer.end(), static_cast<uint8_t *>(in),
                            static_cast<uint8_t *>(in) + len);

      if (pss->rx_buffer.size() > 66000)
        return -1;
      if (!lws_is_final_fragment(wsi))
        break;

      // 2. [DEBUG] Process Directly on Main Thread (Bypass Worker)
      try {

        // A. Decrypt
        auto pkt =
            wasp::parse_packet(pss->rx_buffer, pss->session.get_session_key());

        // B. Write to TUN immediately
        if (!pkt.ip_data.empty()) {
            //wasp::utils::print_packet("CLI-RX", pkt.ip_data.data(), pkt.ip_data.size());
          ssize_t sent =
              tun_write(app.tun_fd, pkt.ip_data.data(), pkt.ip_data.size());
          if (sent > 0) {
            //std::cout << "[RX] Wrote " << sent << " bytes to TUN.\n";
          } else {
            std::cerr << "[RX ERROR] tun_write failed: " << strerror(errno)
                      << "\n";
          }
        }
      } catch (const std::exception &e) {

        std::cerr << "[RX CRITICAL] Decryption Failed: " << e.what() << "\n";
      }

      // 3. Clear buffer for next frame
      pss->rx_buffer.clear();
    }
    break;
  }

  case LWS_CALLBACK_CLIENT_WRITEABLE:
  case LWS_CALLBACK_SERVER_WRITEABLE: {
      // 1. Priority: Handshake
      if (!pss->handshake_tx_queue.empty()) {
          auto& msg = pss->handshake_tx_queue.front();
          std::vector<unsigned char> buf(LWS_PRE + msg.size());
          memcpy(buf.data() + LWS_PRE, msg.data(), msg.size());
          lws_write(wsi, buf.data() + LWS_PRE, msg.size(), LWS_WRITE_TEXT);
          pss->handshake_tx_queue.pop();
          if (!pss->handshake_tx_queue.empty()) lws_callback_on_writable(wsi);
          break;
      }

      // 2. Data: FLUSH the queue (Don't just send one!)
      while (!pss->encrypted_tx_queue.empty()) {
          auto& packet = pss->encrypted_tx_queue.front();

          // Attempt write
          int ret = lws_write(wsi, packet.data() + LWS_PRE, packet.size() - LWS_PRE, LWS_WRITE_BINARY);

          // Handle Error
          if (ret < 0) return -1;

          // Pop the packet we just sent
          pss->encrypted_tx_queue.pop();

          // If socket is full, stop and wait for next callback
          if (lws_send_pipe_choked(wsi)) {
              lws_callback_on_writable(wsi); // Request callback when space is available
              break;
          }
      }
      break;
  }
  case LWS_CALLBACK_EVENT_WAIT_CANCELLED: {
    CryptoResult result;
    while (app.worker_pool->results.try_pop(result)) {
      if (result.is_encrypted) {
        if (result.wsi) {
          if (auto *target_pss =
                  static_cast<WaspSessionData *>(lws_wsi_user(result.wsi))) {
            target_pss->encrypted_tx_queue.push(std::move(result.data));
            lws_callback_on_writable(result.wsi);
          }
        }
      } else {
        // Sanity Check: Is this actually an IPv4 packet?
        if (!result.data.empty()) {
          if (uint8_t version = result.data[0] >> 4; version != 4) {
            std::cerr << "[CRITICAL] Decrypted garbage! Byte0: 0x" << std::hex
                      << static_cast<int>(result.data[0]) << std::dec << "\n";
            continue;
          }
        }

        ssize_t written =
            tun_write(app.tun_fd, result.data.data(), result.data.size());

        if (written > 0) {
          // Success! The OS accepted the packet.

        } else {
          std::cerr << "[TUN] Failed to write decrypted packet to TUN.\n";
        }
      }
    }
    break;
  }
  default:
    break;
  }
  return 0;
}
static struct lws_protocols protocols[] = {
    {"wasp-vpn", callback_wasp, sizeof(WaspSessionData), 66000, 0, nullptr, 0},
    {nullptr, nullptr, 0, 0, 0, nullptr, 0}};

// ============================================================
// Main Function
// ============================================================
int main(int argc, char **argv) {
  if (argc < 2) {
    std::cerr << "Usage: ./wasp_vpn [server | client server_address]\n";
    return 1;
  }
  signal(SIGINT, signal_handler);
  std::string mode = argv[1];
  bool is_server = (mode == "server");
  app.session_manager.set_is_server(is_server);

  unsigned int num_threads = std::thread::hardware_concurrency();
  std::cout << "[INIT] Using " << num_threads << " threads.\n";
  char tun_name[64] = {0};
  if (is_server)
    strcpy(tun_name, "wasp0");
  app.tun_fd = tun_alloc(tun_name);
    if (app.tun_fd < 0) {
        perror("[CRITICAL] Failed to allocate TUN interface");
        return 1;
    }
  std::cout << "[INIT] Interface " << tun_name << " created.\n";

  if (is_server) {
#if defined(__APPLE__)
    run_command(std::format("sudo ifconfig {} 10.0.0.1 10.0.0.2 up", tun_name));
      run_command(std::format("sudo ifconfig {} mtu 1350", tun_name));
#elif defined(__linux__)
      run_command(std::format("sudo ip addr add 10.89.89.1/24 dev {} && sudo ip link set {} up", tun_name, tun_name));
      run_command(std::format("sudo ip link set dev {} mtu 1350", tun_name));
      run_command(std::format("sudo ethtool -K {} tx off", tun_name));
#endif
  }

  app.worker_pool = std::make_unique<WorkerPool>(num_threads);
  struct lws_context_creation_info info = {};
  info.port = is_server ? 7681 : CONTEXT_PORT_NO_LISTEN;
  info.protocols = protocols;
  info.gid = -1;
  info.uid = -1;
    info.count_threads = 1;
  app.lws_ctx = lws_create_context(&info);
  if (!app.lws_ctx) return 1;

    app.worker_pool->set_context(app.lws_ctx);
  if (!is_server) {
    if (argc < 3) {
      std::cerr << "Client mode requires a server address.\n";
      return 1;
    }
    struct lws_client_connect_info ccinfo = {};
    ccinfo.context = app.lws_ctx;
    ccinfo.address = argv[2];
    ccinfo.port = 7681;
    ccinfo.path = "/";
    ccinfo.protocol = protocols[0].name;
    ccinfo.opaque_user_data = static_cast<void *>(tun_name);
    lws_client_connect_via_info(&ccinfo);
  }

  std::thread reader(tun_reader_thread);
  std::cout << "[INIT] Starting Event Loop...\n";
  while (!force_exit) {
    lws_service(app.lws_ctx, 100);
  }

  std::cout << "[SHUTDOWN] Stopping threads...\n";
  app.running = false;
  if (app.tun_fd != -1) {
    close(app.tun_fd);
    app.tun_fd = -1;
  }
  app.worker_pool->stop();
  if (reader.joinable()) {
    reader.join();
  }
  lws_context_destroy(app.lws_ctx);
  std::cout << "[SHUTDOWN] Complete.\n";
  return 0;
}