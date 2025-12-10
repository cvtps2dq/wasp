#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <functional>
#include "wasp_defs.hpp"

struct CryptoTask {
    bool is_encrypt;
    wasp::ByteBuffer data;
    uint32_t session_id;
    wasp::InnerCommand inner_cmd;
    wasp::ByteBuffer session_key; // MUST be a copy for thread safety
    struct lws* wsi;
};

struct CryptoResult {
    bool is_encrypted;
    wasp::ByteBuffer data;
    struct lws* wsi;
};

template<typename T>
class ThreadSafeQueue {
public:
    void push(T value) {
        std::lock_guard lock(mtx_);
        q_.push(std::move(value));
        cond_.notify_one();
    }

    bool pop(T& value) {
        std::unique_lock lock(mtx_);
        cond_.wait(lock, [this]{ return !q_.empty() || stop_; });
        if (stop_ && q_.empty()) return false;
        value = std::move(q_.front());
        q_.pop();
        return true;
    }

    // ====> ADD THIS METHOD <====
    bool try_pop(T& value) {
        std::lock_guard lock(mtx_);
        if (q_.empty()) {
            return false;
        }
        value = std::move(q_.front());
        q_.pop();
        return true;
    }

    void stop() {
        std::lock_guard lock(mtx_);
        stop_ = true;
        cond_.notify_all();
    }

private:
    std::queue<T> q_;
    std::mutex mtx_;
    std::condition_variable cond_;
    bool stop_ = false;
};

class WorkerPool {
public:
    explicit WorkerPool(size_t num_threads);
    ~WorkerPool();
    void stop();

    void submit_task(CryptoTask task);

    ThreadSafeQueue<CryptoTask> tasks;
    ThreadSafeQueue<CryptoResult> results;
    void set_context(struct lws_context* ctx) { lws_ctx_ = ctx; }

private:
    void worker_loop();
    std::vector<std::thread> workers_;
    std::atomic<bool> should_stop_{false};
    struct lws_context* lws_ctx_ = nullptr;
};