//
// Created by cv2 on 09.12.2025.
//
#include "wasp_session.hpp"
#include <iostream>
#include <sstream>

namespace wasp {

    Session::Session(Role role) : role_(role) {
        // Generate my Ephemeral keys immediately
        my_keys_ = crypto::generate_x25519();
    }

    ByteSpan Session::get_session_key() const {
        if (current_state_ != State::ESTABLISHED) {
            throw ProtocolError("Session key requested before handshake completion");
        }
        return session_key_;
    }

    // --- Helper: Tiny Manual JSON Parser ---
    // Looks for "key": "value" or "key":"value"
    std::string Session::extract_json_field(std::string_view json, const std::string_view key) {
        std::string key_to_find;
        key_to_find.reserve(key.length() + 4);
        key_to_find += '"';
        key_to_find += key;
        key_to_find += '"';

        size_t key_pos = json.find(key_to_find);
        if (key_pos == std::string::npos) {
            return "";
        }

        size_t colon_pos = json.find(':', key_pos + key_to_find.length());
        if (colon_pos == std::string::npos) {
            return "";
        }

        size_t value_start = json.find('"', colon_pos);
        if (value_start == std::string::npos) {
            return "";
        }

        size_t value_end = json.find('"', value_start + 1);
        if (value_end == std::string::npos) {
            return "";
        }

        return std::string(json.substr(value_start + 1, value_end - (value_start + 1)));
    }

    // --- Client Entry Point ---
    std::string Session::initiate_handshake() {
        if (role_ != Role::CLIENT) throw ProtocolError("Server cannot initiate handshake");

        current_state_ = State::HANDSHAKE_SENT;

        std::stringstream ss;
        ss << R"({ "type": "HELLO", "kex": "X25519", "pub": ")"
           << crypto::base64_encode(my_keys_.pub_key) << "\" }";
        return ss.str();
    }

    // --- Core Logic ---
    std::optional<std::string> Session::handle_handshake_msg(std::string_view json) {
        std::string type = extract_json_field(json, "type");

        // ---------------------------------------------------------
        // SERVER SIDE LOGIC
        // ---------------------------------------------------------
        if (role_ == Role::SERVER) {

            // 1. Receive Client HELLO -> Send Server HELLO + Salt
            if (current_state_ == State::UNAUTHENTICATED && type == "HELLO") {

                std::string client_pub_b64 = extract_json_field(json, "pub");
                if (client_pub_b64.empty()) throw ProtocolError("Missing client public key");

                // Save Peer Key
                peer_pub_key_ = crypto::base64_decode(client_pub_b64);

                // Generate Salt
                salt_.resize(32);
                crypto::random_bytes(salt_);

                // Derive AES Key immediately (HKDF)
                derive_keys();
                current_state_ = State::AUTHENTICATING; // Waiting for AUTH

                // Construct Response
                std::stringstream ss;
                ss << R"({ "type": "HELLO", "pub": ")" << crypto::base64_encode(my_keys_.pub_key)
                   << R"(", "salt": ")" << crypto::base64_encode(salt_) << "\" }";
                return ss.str();
            }

            // 2. Receive AUTH -> Verify -> Send READY
            else if (current_state_ == State::AUTHENTICATING && type == "AUTH") {

        // Extract Fields
        std::string iv_b64 = extract_json_field(json, "iv");
        std::string payload_b64 = extract_json_field(json, "payload");

        // 1. Decrypt Outer Layer (AES-GCM)
        ByteBuffer iv = crypto::base64_decode(iv_b64);
        ByteBuffer cipher = crypto::base64_decode(payload_b64);
        ByteBuffer plaintext = crypto::aes_gcm_decrypt(session_key_, iv, cipher); // Throws if key is wrong

        std::string plain_str(plaintext.begin(), plaintext.end());

        // 2. Parse Inner Auth JSON
        std::string user = extract_json_field(plain_str, "user");
        std::string timestamp_str = extract_json_field(plain_str, "ts");
        std::string signature_b64 = extract_json_field(plain_str, "sig");

        // 3. Anti-Replay: Check Timestamp
        long long client_ts = std::stoll(timestamp_str);
        long long server_ts = std::time(nullptr);
        if (std::abs(server_ts - client_ts) > 10) { // 10 seconds window
            throw ProtocolError("Replay Attack Detected: Timestamp expired");
        }

        // 4. Validate User
        std::string stored_pass = get_password_for_user(user);
        if (stored_pass.empty()) throw ProtocolError("Unknown User");

        // 5. Anti-MitM: Verify HMAC
        // We verify that the Client has the SAME shared secret as us,
        // signed with the password we both know.

        // Construct the data string exactly as the client did
        std::string data_to_sign = base64_encode_session_key() + timestamp_str;

        ByteBuffer expected_sig = crypto::hmac_sha256(
            ByteSpan((uint8_t*)stored_pass.data(), stored_pass.size()),
            ByteSpan((uint8_t*)data_to_sign.data(), data_to_sign.size())
        );

        ByteBuffer client_sig = crypto::base64_decode(signature_b64);

        if (client_sig != expected_sig) {
            // If this fails, either the password is wrong OR an ISP is intercepting keys.
            throw ProtocolError("Authentication Failed: Invalid Signature (Possible MitM)");
        }

        // Success
        current_state_ = State::ESTABLISHED;
        std::stringstream ss;
        ss << "{ \"type\": \"READY\", \"sid\": \"" << session_id_
           << "\", \"assigned_ip\": \"" << assigned_ip_ << "\" }";
        return ss.str();
    }
        }

        // ---------------------------------------------------------
        // CLIENT SIDE LOGIC
        // ---------------------------------------------------------
        else if (role_ == Role::CLIENT) {

            // 1. Receive Server HELLO -> Send Encrypted AUTH
            if (current_state_ == State::HANDSHAKE_SENT && type == "HELLO") {

                std::string server_pub_b64 = extract_json_field(json, "pub");
                std::string salt_b64 = extract_json_field(json, "salt");

                if (server_pub_b64.empty() || salt_b64.empty()) throw ProtocolError("Invalid Server Hello");

                peer_pub_key_ = crypto::base64_decode(server_pub_b64);
                salt_ = crypto::base64_decode(salt_b64);

                // Derive AES Key
                derive_keys();

                // 1. Timestamp
                long long now = std::time(nullptr);
                std::string ts_str = std::to_string(now);

                // 2. Generate Signature
                // Sign (Shared_Secret + Timestamp) with Password
                std::string data_to_sign = base64_encode_session_key() + ts_str;

                ByteBuffer signature = crypto::hmac_sha256(
                    ByteSpan((uint8_t*)password_.data(), password_.size()),
                    ByteSpan((uint8_t*)data_to_sign.data(), data_to_sign.size())
                );

                // 3. Create JSON Payload
                std::stringstream inner_json;
                inner_json << "{ \"user\": \"" << username_ << "\", "
                           << "\"ts\": \"" << ts_str << "\", "
                           << "\"sig\": \"" << crypto::base64_encode(signature) << "\" }";

                std::string inner_msg = inner_json.str();

                // 4. Encrypt
                std::array<uint8_t, IV_SIZE> iv;
                crypto::random_bytes(iv);
                ByteBuffer encrypted_auth = crypto::aes_gcm_encrypt(
                    session_key_, iv,
                    ByteSpan((uint8_t*)inner_msg.data(), inner_msg.size())
                );

                current_state_ = State::AUTHENTICATING;

                std::stringstream ss;
                ss << "{ \"type\": \"AUTH\", \"iv\": \"" << crypto::base64_encode(iv)
                   << "\", \"payload\": \"" << crypto::base64_encode(encrypted_auth) << "\" }";
                return ss.str();
            }

            // 2. Receive READY -> Switch to Binary
            else if (current_state_ == State::AUTHENTICATING && type == "READY") {

                std::string sid_str = extract_json_field(json, "sid");
                if (sid_str.empty()) throw ProtocolError("Missing Session ID");

                // Parse the IP address assigned by the server
                std::string assigned_ip_str = extract_json_field(json, "assigned_ip");
                if (assigned_ip_str.empty()) throw ProtocolError("Missing Assigned IP from server");

                assigned_ip_ = assigned_ip_str; // Store it in the session

                session_id_ = std::stoul(sid_str);
                current_state_ = State::ESTABLISHED;

                return std::nullopt; // Done! No reply needed.
            }
        }

        return std::nullopt; // Ignore unknown messages or unexpected states
    }

    void Session::derive_keys() {
        // 1. ECDH to get Shared Secret
        ByteBuffer shared_secret = crypto::derive_secret(my_keys_.pkey.get(), peer_pub_key_);

        // 2. HKDF to get AES Session Key
        // Info string matches protocol version
        session_key_ = crypto::hkdf_derive(shared_secret, salt_, "WASP_v1_KEY_GEN");

        std::cout << "[CRYPTO] Key derived on " << (role_ == Role::CLIENT ? "Client" : "Server")
              << ". First 4 bytes: " << std::hex
              << static_cast<int>(session_key_[0]) << " " << static_cast<int>(session_key_[1]) << " "
              << static_cast<int>(session_key_[2]) << " " << static_cast<int>(session_key_[3]) << std::dec << std::endl;
    }
}