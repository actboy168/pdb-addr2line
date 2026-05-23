#pragma once

#include <cstddef>
#include <string>

class MemoryMappedFile {
public:
    MemoryMappedFile() = default;
    MemoryMappedFile(const MemoryMappedFile&) = delete;
    MemoryMappedFile& operator=(const MemoryMappedFile&) = delete;

    MemoryMappedFile(MemoryMappedFile&& other) noexcept;
    MemoryMappedFile& operator=(MemoryMappedFile&& other) noexcept;

    ~MemoryMappedFile();

    bool Open(const char* path, std::string& error);
    void Close();

    const void* Data() const noexcept {
        return base_address_;
    }

    std::size_t Size() const noexcept {
        return size_;
    }

    bool IsOpen() const noexcept {
        return base_address_ != nullptr;
    }

private:
#ifdef _WIN32
    void* file_ = nullptr;
    void* mapping_ = nullptr;
#endif
    void* base_address_ = nullptr;
    std::size_t size_ = 0;
};
