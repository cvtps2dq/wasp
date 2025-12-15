#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <functional>
#include <atomic> // Ensure this is included
#include "wasp_defs.hpp"

// ... CryptoTask and CryptoResult structs remain the same ...
struct CryptoTask {
    bool is_encrypt;
    wasp::ByteBuffer data;
    uint32_t session_id;
    wasp::InnerCommand inner_cmd;
    wasp::ByteBuffer session_key;
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
        std::lock_guard<std::mutex> lock(mtx_);
        q_.push(std::move(value));
        cond_.notify_one();
    }

    bool pop(T& value) {
        std::unique_lock<std::mutex> lock(mtx_);
        cond_.wait(lock, [this]{ return !q_.empty() || stop_; });
        if (stop_ && q_.empty()) return false;
        value = std::move(q_.front());
        q_.pop();
        return true;
    }

    bool try_pop(T& value) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (q_.empty()) {
            return false;
        }
        value = std::move(q_.front());
        q_.pop();
        return true;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mtx_);
        return q_.empty();
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mtx_);
        stop_ = true;
        cond_.notify_all();
    }

    size_t size() {
        std::lock_guard<std::mutex> lock(mtx_);
        return q_.size();
    }

private:
    std::queue<T> q_;
    std::mutex mtx_;
    std::condition_variable cond_;
    bool stop_ = false;
};

class WorkerPool {
public:
    WorkerPool(size_t num_threads);
    ~WorkerPool();
    void stop();

    void submit_task(CryptoTask task);

    // Add context setter we discussed earlier if missing
    void set_context(struct lws_context* ctx) { lws_ctx_ = ctx; }

    ThreadSafeQueue<CryptoTask> tasks;
    ThreadSafeQueue<CryptoResult> results;

private:
    void worker_loop();
    std::vector<std::thread> workers_;
    std::atomic<bool> should_stop_{false};
    struct lws_context* lws_ctx_ = nullptr;
};