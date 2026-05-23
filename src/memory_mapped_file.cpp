#include "memory_mapped_file.h"

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <utility>

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept {
    *this = std::move(other);
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        Close();

        file_ = other.file_;
        mapping_ = other.mapping_;
        base_address_ = other.base_address_;
        size_ = other.size_;

        other.file_ = nullptr;
        other.mapping_ = nullptr;
        other.base_address_ = nullptr;
        other.size_ = 0;
    }

    return *this;
}

MemoryMappedFile::~MemoryMappedFile() {
    Close();
}

bool MemoryMappedFile::Open(const char* path, std::string& error) {
    Close();

    file_ = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        file_ = nullptr;
        error = "failed to open file";
        return false;
    }

    mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping_ == nullptr) {
        error = "failed to create file mapping";
        Close();
        return false;
    }

    base_address_ = MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0);
    if (base_address_ == nullptr) {
        error = "failed to map file into memory";
        Close();
        return false;
    }

    BY_HANDLE_FILE_INFORMATION info = {};
    if (!GetFileInformationByHandle(file_, &info)) {
        error = "failed to read file information";
        Close();
        return false;
    }

    size_ = (static_cast<std::size_t>(info.nFileSizeHigh) << 32) | static_cast<std::size_t>(info.nFileSizeLow);
    error.clear();
    return true;
}

void MemoryMappedFile::Close() {
    if (base_address_ != nullptr) {
        UnmapViewOfFile(base_address_);
        base_address_ = nullptr;
    }

    if (mapping_ != nullptr) {
        CloseHandle(mapping_);
        mapping_ = nullptr;
    }

    if (file_ != nullptr) {
        CloseHandle(file_);
        file_ = nullptr;
    }

    size_ = 0;
}

#else  // POSIX

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <utility>

MemoryMappedFile::MemoryMappedFile(MemoryMappedFile&& other) noexcept {
    *this = std::move(other);
}

MemoryMappedFile& MemoryMappedFile::operator=(MemoryMappedFile&& other) noexcept {
    if (this != &other) {
        Close();

        base_address_ = other.base_address_;
        size_ = other.size_;

        other.base_address_ = nullptr;
        other.size_ = 0;
    }

    return *this;
}

MemoryMappedFile::~MemoryMappedFile() {
    Close();
}

bool MemoryMappedFile::Open(const char* path, std::string& error) {
    Close();

    int fd = ::open(path, O_RDONLY);
    if (fd < 0) {
        error = "failed to open file";
        return false;
    }

    struct stat st;
    if (::fstat(fd, &st) < 0) {
        error = "failed to read file information";
        ::close(fd);
        return false;
    }

    size_ = static_cast<std::size_t>(st.st_size);

    if (size_ == 0) {
        ::close(fd);
        error.clear();
        return true;
    }

    base_address_ = ::mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);

    if (base_address_ == MAP_FAILED) {
        error = "failed to map file into memory";
        base_address_ = nullptr;
        size_ = 0;
        return false;
    }

    error.clear();
    return true;
}

void MemoryMappedFile::Close() {
    if (base_address_ != nullptr) {
        ::munmap(base_address_, size_);
        base_address_ = nullptr;
    }
    size_ = 0;
}

#endif
