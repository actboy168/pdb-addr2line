#include "pe_utils.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

bool ReadPeImageBase(
    const void* image_data,
    std::size_t image_size,
    std::uint64_t& image_base,
    std::string& error) {
    if (image_size < sizeof(IMAGE_DOS_HEADER)) {
        error = "image file is too small for DOS header";
        return false;
    }

    const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(image_data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "image does not have a valid DOS header";
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<std::size_t>(dos->e_lfanew) + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER) > image_size) {
        error = "image does not have a valid NT header";
        return false;
    }

    const auto* nt_base = static_cast<const std::uint8_t*>(image_data) + dos->e_lfanew;
    const auto signature = *reinterpret_cast<const std::uint32_t*>(nt_base);
    if (signature != IMAGE_NT_SIGNATURE) {
        error = "image does not have a valid PE signature";
        return false;
    }

    const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt_base + sizeof(std::uint32_t));
    const auto* optional_header_base = nt_base + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER);

    if (file_header->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
        error = "image optional header is truncated";
        return false;
    }

    const auto magic = *reinterpret_cast<const std::uint16_t*>(optional_header_base);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            error = "image optional header is truncated";
            return false;
        }

        const auto* optional_header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional_header_base);
        image_base = optional_header->ImageBase;
        return true;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const auto* optional_header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional_header_base);
        image_base = optional_header->ImageBase;
        return true;
    }

    error = "image has an unsupported optional header";
    return false;
}


