#include "pe_utils.h"

#include <cstdint>
#include <cstring>

#pragma pack(push, 1)

struct PeDosHeader {
    std::uint16_t e_magic;
    std::uint8_t  reserved[58];
    std::int32_t  e_lfanew;
};

struct PeFileHeader {
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
};

struct PeOptionalHeader32 {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint32_t BaseOfData;
    std::uint32_t ImageBase;
};

struct PeOptionalHeader64 {
    std::uint16_t Magic;
    std::uint8_t  MajorLinkerVersion;
    std::uint8_t  MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
};

#pragma pack(pop)

static constexpr std::uint16_t kDosSignature = 0x5A4D;   // MZ
static constexpr std::uint32_t kPeSignature  = 0x00004550; // PE\0\0
static constexpr std::uint16_t kPe32PlusMagic = 0x020B;
static constexpr std::uint16_t kPe32Magic     = 0x010B;

bool ReadPeImageBase(
    const void* image_data,
    std::size_t image_size,
    std::uint64_t& image_base,
    std::string& error) {
    if (image_size < sizeof(PeDosHeader)) {
        error = "image file is too small for DOS header";
        return false;
    }

    const auto* dos = static_cast<const PeDosHeader*>(image_data);
    if (dos->e_magic != kDosSignature) {
        error = "image does not have a valid DOS header";
        return false;
    }

    if (dos->e_lfanew <= 0 || static_cast<std::size_t>(dos->e_lfanew) + sizeof(std::uint32_t) + sizeof(PeFileHeader) > image_size) {
        error = "image does not have a valid NT header";
        return false;
    }

    const auto* nt_base = static_cast<const std::uint8_t*>(image_data) + dos->e_lfanew;

    std::uint32_t signature;
    std::memcpy(&signature, nt_base, sizeof(signature));
    if (signature != kPeSignature) {
        error = "image does not have a valid PE signature";
        return false;
    }

    const auto* file_header = reinterpret_cast<const PeFileHeader*>(nt_base + sizeof(std::uint32_t));
    const auto* optional_header_base = nt_base + sizeof(std::uint32_t) + sizeof(PeFileHeader);

    if (file_header->SizeOfOptionalHeader < sizeof(PeOptionalHeader32)) {
        error = "image optional header is truncated";
        return false;
    }

    std::uint16_t magic;
    std::memcpy(&magic, optional_header_base, sizeof(magic));

    if (magic == kPe32PlusMagic) {
        if (file_header->SizeOfOptionalHeader < sizeof(PeOptionalHeader64)) {
            error = "image optional header is truncated";
            return false;
        }

        const auto* optional_header = reinterpret_cast<const PeOptionalHeader64*>(optional_header_base);
        image_base = optional_header->ImageBase;
        return true;
    }

    if (magic == kPe32Magic) {
        const auto* optional_header = reinterpret_cast<const PeOptionalHeader32*>(optional_header_base);
        image_base = optional_header->ImageBase;
        return true;
    }

    error = "image has an unsupported optional header";
    return false;
}
