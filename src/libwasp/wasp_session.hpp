#pragma once
#include <optional>
#include <string>
#include "wasp_crypto.hpp"
#include "wasp_defs.hpp"

namespace wasp {

    enum class Role { CLIENT, SERVER };

    class Session {
    public:
        explicit Session(Role role);

        // -- State Machine Drivers --

        // Called to start the process (Client only)
        // Returns: JSON string to send
        std::string initiate_handshake();

        // Called when a Text Frame (JSON) is received during handshake
        // Returns: JSON string to reply, or std::nullopt if we are done or waiting
        std::optional<std::string> handle_handshake_msg(std::string_view incoming_json);

        // -- Accessors --

        [[nodiscard]] State state() const { return current_state_; }
        [[nodiscard]] bool is_established() const { return current_state_ == State::ESTABLISHED; }

        // Returns the derived AES session key (valid only if ESTABLISHED)
        [[nodiscard]] ByteSpan get_session_key() const;
        [[nodiscard]] uint32_t get_session_id() const { return session_id_; }

        // Server only: assign ID
        void set_session_id(const uint32_t id) { session_id_ = id; }
        void set_assigned_ip(std::string ip) { assigned_ip_ = std::move(ip); }
        [[nodiscard]] Role get_role() const { return role_;}
        std::string get_assigned_ip() {return assigned_ip_;}

        void set_credentials(std::string user, std::string password) {
            username_ = std::move(user);
            password_ = std::move(password);
        }

        // For Server Mode: Simple User Database (In-Memory)
        // In production, move this to SessionManager or a DB
        static std::string get_password_for_user(const std::string& user) {
            // HARDCODED FOR DEMO
            if (user == "admin") return "secret_password_123";
            return ""; // User not found
        }

    private:
        Role role_;
        State current_state_ = State::UNAUTHENTICATED;

        // Crypto State
        crypto::KeyPair my_keys_;
        ByteBuffer peer_pub_key_;
        ByteBuffer salt_;
        ByteBuffer session_key_;
        uint32_t session_id_ = 0;

        std::string username_;
        std::string password_;

        // Helpers
        void derive_keys();
        static std::string extract_json_field(std::string_view json, std::string_view key);
        std::string assigned_ip_;

        std::string base64_encode_session_key() {
            return crypto::base64_encode(session_key_);
        }
    };

}