#pragma once
#include "wasp_defs.hpp"
#include "wasp_crypto.hpp"
#include <string>
#include <optional>

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

    private:
        Role role_;
        State current_state_ = State::UNAUTHENTICATED;

        // Crypto State
        crypto::KeyPair my_keys_;
        ByteBuffer peer_pub_key_;
        ByteBuffer salt_;
        ByteBuffer session_key_;
        uint32_t session_id_ = 0;

        // Helpers
        void derive_keys();
        static std::string extract_json_field(std::string_view json, std::string_view key);
        std::string assigned_ip_;
    };

}