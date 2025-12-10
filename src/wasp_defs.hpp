#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <span>
#include <stdexcept>

namespace wasp {

    // --- Constants ---
    constexpr uint8_t VERSION = 0x1;
    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;
    constexpr size_t KEY_SIZE = 32;
    constexpr size_t SESSION_ID_SIZE = 3;

    // Outer Header = Ver/Type (1) + SessionID (3) + IV (12) = 16 bytes
    constexpr size_t HEADER_SIZE = 1 + SESSION_ID_SIZE + IV_SIZE;

    // Inner Header = Command (1) + Length (2) = 3 bytes
    constexpr size_t INNER_HEADER_SIZE = 3;

    // --- Enums ---

    // 1. Wire Message Type (Outer Header)
    enum class MessageType : uint8_t {
        HANDSHAKE = 0x0,
        DATA      = 0x1,
        CONTROL   = 0x2,
        ERROR     = 0x3,
        UNKNOWN   = 0xF
    };

    // 2. Inner Command (Decrypted Payload)
    enum class InnerCommand : uint8_t {
        IPV4 = 0x1,
        IPV6 = 0x2,
        KEEPALIVE = 0x3
    };

    // 3. Session State (Used by Session Logic)
    enum class State {
        UNAUTHENTICATED, // Waiting for Hello
        HANDSHAKE_SENT,  // Sent Hello, waiting for Server Hello
        AUTHENTICATING,  // Calculating keys, sending Auth
        ESTABLISHED,     // Binary mode
        FAILED
    };

    // --- Types ---
    using ByteBuffer = std::vector<uint8_t>;
    using ByteSpan = std::span<const uint8_t>;

    // Exception for Protocol Violations
    class ProtocolError final : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // The Result Structure for the Parser
    struct ParsedPacket {
        // Metadata from outer header
        uint8_t version;
        MessageType type;
        uint32_t session_id;

        // Metadata from inner header
        InnerCommand inner_cmd;

        // The actual payload (IP packet), padding stripped
        ByteBuffer ip_data;
    };

    // --- Function Prototypes ---
    ParsedPacket parse_packet(ByteSpan frame, ByteSpan session_key);

    ByteBuffer build_data_packet(
        uint32_t session_id,
        ByteSpan session_key,
        InnerCommand cmd,
        ByteSpan ip_data
    );
}