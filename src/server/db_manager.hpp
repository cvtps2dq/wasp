#pragma once

#include <sqlite_orm/sqlite_orm.h>
#include <string>
#include <vector>
#include <random>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <optional>

// Use the namespace for brevity
using namespace sqlite_orm;

namespace wasp::db {

    // ==========================================
    // DATA MODELS
    // ==========================================
    struct User {
        int id;
        std::string username;
        std::string password_hash; // PBKDF2 Hash
        std::string salt;          // Random Salt
        bool is_approved;          // Requires Admin Approval
        long long created_at;      // Timestamp
    };

    // ==========================================
    // CRYPTO HELPERS (Password Hashing)
    // ==========================================
    inline std::string generate_salt() {
        unsigned char buf[16];
        RAND_bytes(buf, sizeof(buf));
        std::stringstream ss;
        for(auto b : buf) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    }

    inline std::string hash_password(const std::string& password, const std::string& salt) {
        // PBKDF2 with SHA256, 10000 iterations
        unsigned char hash[32];
        PKCS5_PBKDF2_HMAC(
            password.c_str(), password.length(),
            reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
            10000,
            EVP_sha256(),
            32, hash
        );

        std::stringstream ss;
        for(auto b : hash) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        return ss.str();
    }

    // ==========================================
    // DATABASE MANAGER
    // ==========================================
    inline auto init_storage(const std::string& path = "wasp.db") {
        return make_storage(path,
            make_table("users",
                make_column("id", &User::id, autoincrement(), primary_key()),
                make_column("username", &User::username, unique()),
                make_column("password_hash", &User::password_hash),
                make_column("salt", &User::salt),
                make_column("is_approved", &User::is_approved),
                make_column("created_at", &User::created_at)
            )
        );
    }

    // Typedef for the storage object
    using Storage = decltype(init_storage(""));

    class UserManager {
    public:
        UserManager(const std::string& db_path) : storage_(init_storage(db_path)) {
            storage_.sync_schema(); // Auto-create tables if missing
        }

        // --- Management Actions ---

        bool add_user(const std::string& username, const std::string& password) {
            auto count = storage_.count<User>(where(c(&User::username) == username));
            if (count > 0) return false; // Exists

            std::string salt = generate_salt();
            std::string hash = hash_password(password, salt);

            User user{ -1, username, hash, salt, false, (long long)std::time(nullptr) };
            storage_.insert(user);
            return true;
        }

        bool approve_user(const std::string& username) {
            auto users = storage_.get_all<User>(where(c(&User::username) == username));
            if (users.empty()) return false;

            User& u = users[0];
            u.is_approved = true;
            storage_.update(u);
            return true;
        }

        bool delete_user(const std::string& username) {
            auto count = storage_.count<User>(where(c(&User::username) == username));
            if (count == 0) return false;

            storage_.remove_all<User>(where(c(&User::username) == username));
            return true;
        }

        // --- Authentication ---

        // Returns true if password is correct AND user is approved
        bool authenticate(const std::string& username, const std::string& password) {
            auto users = storage_.get_all<User>(where(c(&User::username) == username));
            if (users.empty()) return false;

            const User& u = users[0];
            if (!u.is_approved) return false;

            std::string check_hash = hash_password(password, u.salt);
            return check_hash == u.password_hash;
        }

        std::vector<User> list_users() {
            return storage_.get_all<User>();
        }

    private:
        Storage storage_;
    };
}