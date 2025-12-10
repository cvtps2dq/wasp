#include "wasp_defs.hpp"
#include "wasp_crypto.hpp"
#include <cstring>
#include <vector>
#include <array>
#include <stdexcept>
#include <libwebsockets.h> // For LWS_PRE

namespace wasp {

    // ==========================================
    // PARSE PACKET (RX)
    // ==========================================
    ParsedPacket parse_packet(ByteSpan frame, ByteSpan session_key) {
        // 1. Minimum Size Check
        if (frame.size() < HEADER_SIZE + TAG_SIZE) {
            throw ProtocolError("Frame too short");
        }

        // 2. Parse Outer Header (Cleartext)
        const uint8_t meta = frame[0];
        const uint8_t ver = meta >> 4;
        const auto type = static_cast<MessageType>(meta & 0x0F);

        if (ver != VERSION) {
            throw ProtocolError("Version mismatch");
        }

        // Parse Session ID
        uint32_t sid = (static_cast<uint32_t>(frame[1]) << 16) |
                       (static_cast<uint32_t>(frame[2]) << 8)  |
                       static_cast<uint32_t>(frame[3]);

        // Extract IV
        ByteSpan iv_span = frame.subspan(4, IV_SIZE);

        // 3. Decrypt
        ByteSpan ciphertext_with_tag = frame.subspan(HEADER_SIZE);
        ByteBuffer decrypted_raw = crypto::aes_gcm_decrypt(session_key, iv_span, ciphertext_with_tag);

        // 4. Parse Inner Header [Cmd][Len]
        if (decrypted_raw.size() < INNER_HEADER_SIZE) {
            throw ProtocolError("Decrypted payload too short");
        }

        const uint8_t cmd_byte = decrypted_raw[0];
        const auto inner_cmd = static_cast<InnerCommand>(cmd_byte);

        uint16_t data_len = (static_cast<uint16_t>(decrypted_raw[1]) << 8) |
                            static_cast<uint16_t>(decrypted_raw[2]);

        if (decrypted_raw.size() < INNER_HEADER_SIZE + data_len) {
            throw ProtocolError("Inner length check failed");
        }

        // 5. Extract IP Payload
        ByteBuffer ip_payload;
        ip_payload.reserve(data_len);
        auto data_start = decrypted_raw.begin() + INNER_HEADER_SIZE;
        ip_payload.insert(ip_payload.end(), data_start, data_start + data_len);

        return ParsedPacket{ver, type, sid, inner_cmd, std::move(ip_payload)};
    }

    // ==========================================
    // BUILD PACKET (TX)
    // ==========================================
    ByteBuffer build_data_packet(
        uint32_t session_id,
        ByteSpan session_key,
        InnerCommand cmd,
        ByteSpan ip_data
    ) {
        // 1. Prepare Inner Payload (Cmd + Len + Data + Padding)
        size_t raw_size = INNER_HEADER_SIZE + ip_data.size();
        size_t padded_size = (raw_size + 15) & ~15; // Align to 16 bytes
        size_t padding_len = padded_size - raw_size;

        ByteBuffer inner_plaintext;
        inner_plaintext.reserve(padded_size);

        inner_plaintext.push_back(static_cast<uint8_t>(cmd));
        inner_plaintext.push_back((ip_data.size() >> 8) & 0xFF);
        inner_plaintext.push_back(ip_data.size() & 0xFF);
        inner_plaintext.insert(inner_plaintext.end(), ip_data.begin(), ip_data.end());

        // Zero Padding
        for(size_t i=0; i<padding_len; ++i) inner_plaintext.push_back(0x00);

        // 2. Encrypt
        std::array<uint8_t, IV_SIZE> iv;
        crypto::random_bytes(iv);
        ByteBuffer encrypted = crypto::aes_gcm_encrypt(session_key, iv, inner_plaintext);

        // 3. Build Frame with LWS Padding
        ByteBuffer final_frame(LWS_PRE + HEADER_SIZE + encrypted.size());
        uint8_t* p = final_frame.data() + LWS_PRE;

        // Header
        *p++ = (VERSION << 4) | (static_cast<uint8_t>(MessageType::DATA) & 0x0F);
        *p++ = (session_id >> 16) & 0xFF;
        *p++ = (session_id >> 8) & 0xFF;
        *p++ = session_id & 0xFF;

        // IV
        std::memcpy(p, iv.data(), iv.size());
        p += iv.size();

        // Ciphertext + Tag
        std::memcpy(p, encrypted.data(), encrypted.size());

        return final_frame;
    }
}