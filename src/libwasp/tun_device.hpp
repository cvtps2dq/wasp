#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace wasp {
    class TunDevice {
    public:
        TunDevice(const std::string& name, bool is_server);
        ~TunDevice();

        int get_fd() const { return fd_; }
        std::string get_name() const { return name_; }

        // Reads from OS -> Buffer. Returns bytes read.
        // Handles: Buffer resizing, Headers (Mac), Checksums (Linux Server)
        ssize_t read(std::vector<uint8_t>& buffer);

        // Writes Buffer -> OS.
        // Handles: Headers (Mac)
        ssize_t write(const std::vector<uint8_t>& buffer);

    private:
        int fd_ = -1;
        std::string name_;
        bool is_server_;
    };
}