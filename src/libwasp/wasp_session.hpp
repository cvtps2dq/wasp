#pragma once
#include "wasp_defs.hpp"
#include "wasp_crypto.hpp"
#include <string>
#include <optional>
#include <functional> // Required for std::function

namespace wasp {

    enum class Role { CLIENT, SERVER };

    // Callback signature: (username, password) -> bool (is_valid)
    using CredentialValidator = std::function<bool(const std::string&, const std::string&)>;

    class Session {
    public:
        Session(Role role);

        // -- State Machine Drivers --

        // Called to start the process (Client only)
        std::string initiate_handshake();

        // Called when a Text Frame (JSON) is received during handshake
        // Returns: JSON string to reply, or std::nullopt if we are done or waiting
        std::optional<std::string> handle_handshake_msg(std::string_view incoming_json);

        // -- Configuration --

        // Client: Set credentials to send to server
        void set_credentials(std::string user, std::string password) {
            username_ = std::move(user);
            password_ = std::move(password);
        }

        // Server: Set the logic to verify credentials (e.g., DB lookup)
        void set_validator(CredentialValidator v) {
            credentials_validator_ = std::move(v);
        }

        // -- Accessors --

        State state() const { return current_state_; }
        bool is_established() const { return current_state_ == State::ESTABLISHED; }

        ByteSpan get_session_key() const;
        uint32_t get_session_id() const { return session_id_; }

        void set_session_id(uint32_t id) { session_id_ = id; }
        void set_assigned_ip(std::string ip) { assigned_ip_ = std::move(ip); }
        Role get_role() const { return role_; }
        std::string get_assigned_ip() const { return assigned_ip_; }

    private:
        Role role_;
        State current_state_ = State::UNAUTHENTICATED;

        // Crypto State
        crypto::KeyPair my_keys_;
        ByteBuffer peer_pub_key_;
        ByteBuffer salt_;
        ByteBuffer session_key_;
        uint32_t session_id_ = 0;
        std::string assigned_ip_;

        // Auth Data
        std::string username_;
        std::string password_;
        CredentialValidator credentials_validator_;

        // Helpers
        void derive_keys();
        std::string extract_json_field(std::string_view json, std::string_view key);
        std::string base64_encode_session_key();
    };

}