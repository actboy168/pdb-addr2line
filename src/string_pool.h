#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>

class StringPool {
public:
    std::uint32_t Intern(std::string_view value) {
        const auto it = index_by_value_.find(value);
        if (it != index_by_value_.end()) {
            return it->second;
        }

        const std::uint32_t index = static_cast<std::uint32_t>(values_.size());
        values_.emplace_back(value);
        index_by_value_.emplace(values_.back(), index);
        return index;
    }

    std::uint32_t Intern(const std::string& value) {
        return Intern(std::string_view(value));
    }

    std::uint32_t Intern(const char* value) {
        return Intern(std::string_view(value));
    }

    void Clear() {
        values_.clear();
        index_by_value_.clear();
    }

    std::uint32_t Intern(std::string&& value) {
        const auto it = index_by_value_.find(value);
        if (it != index_by_value_.end()) {
            return it->second;
        }

        const std::uint32_t index = static_cast<std::uint32_t>(values_.size());
        values_.push_back(std::move(value));
        index_by_value_.emplace(values_.back(), index);
        return index;
    }

    const std::string& Get(std::uint32_t index) const {
        return values_[index];
    }

private:
    struct StringViewHash {
        using is_transparent = void;

        std::size_t operator()(std::string_view value) const noexcept {
            return std::hash<std::string_view>{}(value);
        }
    };

    struct StringViewEqual {
        using is_transparent = void;

        bool operator()(std::string_view lhs, std::string_view rhs) const noexcept {
            return lhs == rhs;
        }
    };

    std::deque<std::string> values_;
    std::unordered_map<std::string_view, std::uint32_t, StringViewHash, StringViewEqual> index_by_value_;
};
