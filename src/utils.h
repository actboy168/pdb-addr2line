#pragma once

#include <cstdint>
#include <string_view>

bool ParseInteger64(std::string_view text, std::uint64_t& value);
