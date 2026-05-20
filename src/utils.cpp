#include "utils.h"

#include <charconv>
#include <iomanip>
#include <sstream>

bool ParseInteger64(std::string_view text, std::uint64_t& value) {
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }

    if (text.empty()) {
        return false;
    }

    const char* begin = text.data();
    const char* end = text.data() + text.size();
    auto result = std::from_chars(begin, end, value, base);
    return result.ec == std::errc() && result.ptr == end;
}

bool ParseInteger(std::string_view text, std::uint32_t& value) {
    std::uint64_t parsed = 0;
    if (!ParseInteger64(text, parsed) || parsed > 0xFFFFFFFFull) {
        return false;
    }

    value = static_cast<std::uint32_t>(parsed);
    return true;
}

std::string FormatHex(std::uint32_t value, int width) {
    std::ostringstream oss;
    oss << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(width) << value;
    return oss.str();
}
