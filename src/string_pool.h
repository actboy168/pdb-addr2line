#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

class StringPool {
public:
    void Clear() {
        values_.clear();
        index_by_value_.clear();
    }

    std::uint32_t Intern(std::string value) {
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
    std::vector<std::string> values_;
    std::unordered_map<std::string, std::uint32_t> index_by_value_;
};
