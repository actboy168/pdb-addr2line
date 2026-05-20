#pragma once

#include <cstdint>
#include <string>

bool ReadPeImageBase(
    const void* image_data,
    std::size_t image_size,
    std::uint64_t& image_base,
    std::string& error);
