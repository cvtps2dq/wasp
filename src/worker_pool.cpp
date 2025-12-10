#include "worker_pool.hpp"

#include <iostream>
#include <libwebsockets/lws-service.h>

WorkerPool::WorkerPool(const size_t num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] { this->worker_loop(); });
    }
}

WorkerPool::~WorkerPool() {
    if (!should_stop_) {
        stop();
    }
}

void WorkerPool::stop() {
    should_stop_ = true;
    tasks.stop();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void WorkerPool::submit_task(CryptoTask task) {
    tasks.push(std::move(task));
}

void WorkerPool::worker_loop() {
    while (!should_stop_) {
        CryptoTask task;
        if (tasks.pop(task)) {
            try {
                if (task.is_encrypt) {
                    wasp::ByteBuffer frame = wasp::build_data_packet(
                        task.session_id,
                        task.session_key,
                        task.inner_cmd,
                        task.data
                    );
                    results.push({true, std::move(frame), task.wsi});
                } else { // Decrypt
                    auto pkt = wasp::parse_packet(task.data, task.session_key);
                    results.push({false, std::move(pkt.ip_data), task.wsi});
                }

                if (lws_ctx_) {
                    lws_cancel_service(lws_ctx_);
                }
            } catch (const std::exception& e) {
                // Silently drop bad packets in production
                std::cerr << "[CRYPTO ERROR] Worker exception: " << e.what() << std::endl;
            }
        }
    }
}