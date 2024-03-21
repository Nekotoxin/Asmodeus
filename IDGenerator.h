#pragma once

#include <mutex>

class IdGenerator {
private:
    long id;
    std::mutex mtx; // Mutex for thread-safe ID increment

public:
    // Constructor with an initial ID
    IdGenerator(long initialId) : id(initialId) {}

    // Default constructor initializes ID to 0
    IdGenerator() : IdGenerator(0L) {}

    // Increment and return the next ID in a thread-safe manner
    long nextId() {
        std::lock_guard<std::mutex> lock(mtx); // Lock the mutex during ID increment
        return ++id;
    }
};
