#pragma once

#include "types.h"

#include <cstdint>
#include <optional>
#include <vector>

bool ReadCompressedAnnotation(const std::uint8_t*& current, const std::uint8_t* end, std::uint32_t& value);
int DecodeSignedAnnotation(std::uint32_t operand);
bool ReadDecodedAnnotation(const std::uint8_t*& current, const std::uint8_t* end, DecodedAnnotation& annotation);

template <typename F>
std::vector<InlineRange> BuildInlineRanges(
    const std::uint8_t* data,
    std::size_t size,
    const InlineeSourceInfo& base_source,
    F&& resolve_source_index) {
    std::vector<InlineRange> ranges;

    std::uint32_t code_offset = 0;
    int line_offset = 0;
    std::optional<std::uint32_t> range_start;
    std::optional<std::uint32_t> range_end;
    std::optional<int> current_line_offset;
    std::optional<int> next_line_offset;
    InlineeSourceInfo current_source = base_source;
    std::optional<InlineeSourceInfo> next_source;

    auto commit_range = [&]() {
        if (!range_start || !range_end || !current_line_offset) {
            return false;
        }

        ranges.push_back({
            *range_start,
            *range_end,
            current_source.source_index,
            *current_line_offset,
            current_source.has_source
        });

        if (next_source) {
            current_source = *next_source;
        }
        if (next_line_offset) {
            current_line_offset = *next_line_offset;
            next_line_offset.reset();
        }

        range_start = range_end;
        range_end.reset();
        next_source.reset();
        return true;
    };

    auto update_code_offset = [&](std::uint32_t delta) {
        if (!range_start) {
            range_start = code_offset;
        } else if (!range_end) {
            range_end = *range_start + delta;
        }
    };

    auto update_line_offset = [&](int delta) {
        line_offset += delta;
        if (!range_start || !current_line_offset) {
            current_line_offset = line_offset;
        } else {
            next_line_offset = line_offset;
        }
    };

    auto update_file = [&](std::uint32_t file_checksum_offset) {
        InlineeSourceInfo source = base_source;
        if (const std::optional<std::uint32_t> source_index = resolve_source_index(file_checksum_offset)) {
            source.source_index = *source_index;
            source.has_source = true;
        } else {
            source.has_source = false;
        }

        if (!range_start) {
            current_source = source;
        } else {
            next_source = source;
        }
    };

    const std::uint8_t* current = data;
    const std::uint8_t* const end = data + size;
    while (current < end) {
        DecodedAnnotation annotation;
        if (!ReadDecodedAnnotation(current, end, annotation)) {
            break;
        }

        switch (annotation.op) {
        case BinaryAnnotationOpCode::CodeOffset:
        case BinaryAnnotationOpCode::ChangeCodeOffset:
        case BinaryAnnotationOpCode::ChangeCodeOffsetBase:
            code_offset += annotation.u1;
            update_code_offset(annotation.u1);
            break;

        case BinaryAnnotationOpCode::ChangeCodeLength:
            update_code_offset(annotation.u1);
            break;

        case BinaryAnnotationOpCode::ChangeFile:
            update_file(annotation.u1);
            break;

        case BinaryAnnotationOpCode::ChangeLineOffset:
            update_line_offset(annotation.s1);
            break;

        case BinaryAnnotationOpCode::ChangeCodeOffsetAndLineOffset:
            code_offset += annotation.u1;
            update_code_offset(annotation.u1);
            update_line_offset(annotation.s1);
            break;

        case BinaryAnnotationOpCode::ChangeCodeLengthAndCodeOffset:
            code_offset += annotation.u2;
            update_code_offset(annotation.u2);
            update_code_offset(annotation.u1);
            break;

        case BinaryAnnotationOpCode::Invalid:
        case BinaryAnnotationOpCode::ChangeLineEndDelta:
        case BinaryAnnotationOpCode::ChangeRangeKind:
        case BinaryAnnotationOpCode::ChangeColumnStart:
        case BinaryAnnotationOpCode::ChangeColumnEndDelta:
        case BinaryAnnotationOpCode::ChangeColumnEnd:
            break;
        }

        commit_range();
    }

    return ranges;
}
