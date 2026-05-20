#pragma once

#include <cstdint>
#include <string>
#include <string_view>

bool ParseInteger64(std::string_view text, std::uint64_t& value);
bool ParseInteger(std::string_view text, std::uint32_t& value);
std::string FormatHex(std::uint32_t value, int width = 8);
