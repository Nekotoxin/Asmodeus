#pragma once

#include <mutex>

class IdGenerator {
private:
    __u64 id;
    std::mutex mtx; // Mutex for thread-safe ID increment

public:
    // Constructor with an initial ID
    IdGenerator(__u64 initialId) : id(initialId) {}

    // Default constructor initializes ID to 0
    IdGenerator() : IdGenerator(0ULL) {}

    // Increment and return the next ID in a thread-safe manner
    __u64 nextId() {
        std::lock_guard<std::mutex> lock(mtx); // Lock the mutex during ID increment
        return ++id;
    }
};
