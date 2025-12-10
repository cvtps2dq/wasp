#include "wasp_session.hpp"
#include <iostream>
#include <sstream>
#include <format>
#include <array>

namespace wasp {

    Session::Session(Role role) : role_(role) {
        my_keys_ = crypto::generate_x25519();
    }

    ByteSpan Session::get_session_key() const {
        if (current_state_ != State::ESTABLISHED) {
            throw ProtocolError("Session key requested before handshake completion");
        }
        return session_key_;
    }

    // --- Helper: Manual JSON Parser ---
    std::string Session::extract_json_field(std::string_view json, std::string_view key) {
        std::string key_to_find = "\"";
        key_to_find += key;
        key_to_find += "\"";

        size_t key_pos = json.find(key_to_find);
        if (key_pos == std::string::npos) return "";

        size_t colon_pos = json.find(':', key_pos + key_to_find.length());
        if (colon_pos == std::string::npos) return "";

        size_t value_start = json.find('"', colon_pos);
        if (value_start == std::string::npos) return "";

        size_t value_end = json.find('"', value_start + 1);
        if (value_end == std::string::npos) return "";

        return std::string(json.substr(value_start + 1, value_end - (value_start + 1)));
    }

    std::string Session::base64_encode_session_key() {
        return crypto::base64_encode(session_key_);
    }

    // --- Client Entry Point ---
    std::string Session::initiate_handshake() {
        if (role_ != Role::CLIENT) throw ProtocolError("Server cannot initiate handshake");

        current_state_ = State::HANDSHAKE_SENT;

        std::stringstream ss;
        ss << "{ \"type\": \"HELLO\", \"kex\": \"X25519\", \"pub\": \""
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

                peer_pub_key_ = crypto::base64_decode(client_pub_b64);

                salt_.resize(32);
                crypto::random_bytes(salt_);

                derive_keys();
                current_state_ = State::AUTHENTICATING;

                std::stringstream ss;
                ss << "{ \"type\": \"HELLO\", \"pub\": \"" << crypto::base64_encode(my_keys_.pub_key)
                   << "\", \"salt\": \"" << crypto::base64_encode(salt_) << "\" }";
                return ss.str();
            }

            // 2. Receive AUTH -> Validate via Callback -> Send READY
            else if (current_state_ == State::AUTHENTICATING && type == "AUTH") {

                std::string iv_b64 = extract_json_field(json, "iv");
                std::string payload_b64 = extract_json_field(json, "payload");

                if (iv_b64.empty() || payload_b64.empty()) throw ProtocolError("Missing auth data");

                // Decrypt
                ByteBuffer iv = crypto::base64_decode(iv_b64);
                ByteBuffer cipher = crypto::base64_decode(payload_b64);
                ByteBuffer plaintext = crypto::aes_gcm_decrypt(session_key_, iv, cipher);

                std::string plain_str(plaintext.begin(), plaintext.end());

                // Parse Credentials
                std::string user = extract_json_field(plain_str, "user");
                std::string pass = extract_json_field(plain_str, "pass");

                // === VALIDATION ===
                if (!credentials_validator_) {
                    throw ProtocolError("Server Internal Error: No Auth Validator set");
                }

                if (!credentials_validator_(user, pass)) {
                    throw ProtocolError("Authentication Failed: Invalid Credentials");
                }
                // ==================

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

                derive_keys();

                // === PREPARE AUTH ===
                std::stringstream inner_json;
                inner_json << "{ \"user\": \"" << username_ << "\", "
                           << "\"pass\": \"" << password_ << "\" }";

                std::string inner_msg = inner_json.str();

                // Encrypt
                std::array<uint8_t, IV_SIZE> iv;
                crypto::random_bytes(iv);
                ByteBuffer encrypted_auth = crypto::aes_gcm_encrypt(
                    session_key_, iv,
                    ByteSpan(reinterpret_cast<const uint8_t*>(inner_msg.data()), inner_msg.size())
                );

                current_state_ = State::AUTHENTICATING;

                std::stringstream ss;
                ss << "{ \"type\": \"AUTH\", \"iv\": \"" << crypto::base64_encode(iv)
                   << "\", \"payload\": \"" << crypto::base64_encode(encrypted_auth) << "\" }";
                return ss.str();
            }

            // 2. Receive READY -> Established
            else if (current_state_ == State::AUTHENTICATING && type == "READY") {

                std::string sid_str = extract_json_field(json, "sid");
                std::string ip_str = extract_json_field(json, "assigned_ip");

                if (sid_str.empty() || ip_str.empty()) throw ProtocolError("Missing Session Info");

                session_id_ = std::stoul(sid_str);
                assigned_ip_ = ip_str;
                current_state_ = State::ESTABLISHED;

                return std::nullopt;
            }
        }

        return std::nullopt;
    }

    void Session::derive_keys() {
        ByteBuffer shared_secret = crypto::derive_secret(my_keys_.pkey.get(), peer_pub_key_);
        session_key_ = crypto::hkdf_derive(shared_secret, salt_, "WASP_v1_KEY_GEN");
    }
}