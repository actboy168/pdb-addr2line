#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class QueryKind {
    Rva,
    Va,
};

struct CommandLine {
    std::string pdb_path;
    std::string image_path;
    std::uint64_t image_base_override = 0;
    QueryKind query_kind = QueryKind::Rva;
    std::vector<std::string> query_values;
};

struct Query {
    std::string original;
    std::uint32_t rva = 0;
};

struct LineEntry {
    std::uint32_t rva = 0;
    std::uint32_t code_size = 0;
    std::uint32_t section_offset = 0;
    std::uint32_t line_start = 0;
    std::uint32_t line_end = 0;
    std::uint16_t section_index = 0;
    std::uint32_t source_index = 0;
    std::uint32_t module_index = 0;
    std::uint32_t object_index = 0;
    bool is_statement = false;
};

struct FunctionEntry {
    std::uint32_t rva = 0;
    std::uint32_t code_size = 0;
    std::uint32_t name_index = 0;
    std::uint32_t module_index = 0;
    std::uint32_t object_index = 0;
};

struct InlineeSourceInfo {
    std::uint32_t source_index = 0;
    std::uint32_t line_start = 0;
    bool has_source = false;
};

struct InlineRange {
    std::uint32_t start_offset = 0;
    std::uint32_t end_offset = 0;
    std::uint32_t source_index = 0;
    int line_offset = 0;
    bool has_source = false;
};

struct InlineSiteEntry {
    std::uint32_t function_rva = 0;
    std::uint32_t inlinee_id = 0;
    std::uint32_t name_index = 0;
    std::uint32_t module_index = 0;
    std::uint32_t object_index = 0;
    InlineeSourceInfo base_source;
    std::vector<InlineRange> ranges;
    std::vector<std::size_t> children;
    bool name_resolved = false;
};

struct InlineFrame {
    std::uint32_t name_index = 0;
    std::uint32_t source_index = 0;
    std::uint32_t line = 0;
    bool has_source = false;
};

struct PendingFilename {
    std::uint32_t file_checksum_offset = 0;
    std::uint32_t names_filename_offset = 0;
};

enum class ScopeKind {
    Function,
    InlineSite,
    Other,
};

struct ScopeEntry {
    ScopeKind kind = ScopeKind::Other;
    std::size_t inline_index = 0;
};

enum class BinaryAnnotationOpCode : std::uint32_t {
    Invalid,
    CodeOffset,
    ChangeCodeOffsetBase,
    ChangeCodeOffset,
    ChangeCodeLength,
    ChangeFile,
    ChangeLineOffset,
    ChangeLineEndDelta,
    ChangeRangeKind,
    ChangeColumnStart,
    ChangeColumnEndDelta,
    ChangeCodeOffsetAndLineOffset,
    ChangeCodeLengthAndCodeOffset,
    ChangeColumnEnd,
};

struct DecodedAnnotation {
    BinaryAnnotationOpCode op = BinaryAnnotationOpCode::Invalid;
    std::uint32_t u1 = 0;
    std::uint32_t u2 = 0;
    int s1 = 0;
};
