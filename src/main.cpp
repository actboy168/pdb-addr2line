#include "types.h"
#include "utils.h"
#include "resolver.h"
#include "memory_mapped_file.h"

#include <iostream>
#include <optional>
#include <string>

namespace {

std::string Usage() {
    return
        "Usage:\n"
        "  pdb-addr2line <pdb-path> <address> [more-address...]\n"
        "  pdb-addr2line <pdb-path> --image <binary-path> <virtual-address> [more-virtual-address...]\n"
        "  pdb-addr2line <pdb-path> --image-base <hex> <virtual-address> [more-virtual-address...]\n";
}

bool ParseCommandLine(int argc, char** argv, CommandLine& command_line, std::string& error) {
    if (argc < 3) {
        error = "not enough arguments";
        return false;
    }

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "--image") {
            if (i + 1 >= argc) {
                error = "--image requires a path";
                return false;
            }
            command_line.image_path = argv[++i];
            continue;
        }

        if (arg == "--image-base") {
            if (i + 1 >= argc) {
                error = "--image-base requires a hex value";
                return false;
            }
            if (!ParseInteger64(argv[++i], command_line.image_base_override) || command_line.image_base_override == 0) {
                error = "--image-base value is not a valid non-zero integer";
                return false;
            }
            continue;
        }

        if (!arg.empty() && arg[0] == '-') {
            error = "unknown option: " + arg;
            return false;
        }

        if (command_line.pdb_path.empty()) {
            command_line.pdb_path = arg;
            continue;
        }

        command_line.query_values.push_back(arg);
    }

    if (command_line.pdb_path.empty()) {
        error = "missing pdb path";
        return false;
    }
    if (command_line.query_values.empty()) {
        error = "missing address input";
        return false;
    }

    command_line.query_kind =
        (!command_line.image_path.empty() || command_line.image_base_override != 0)
        ? QueryKind::Va
        : QueryKind::Rva;

    return true;
}

void PrintFrameLocation(
    const char* name,
    const char* source_file,
    std::uint32_t line) {
    std::cout << name;
    if (source_file != nullptr) {
        std::cout << " at " << source_file << ':' << line;
    }
}

void PrintResult(
    const std::string& original,
    const LineEntry* entry,
    const FunctionEntry* function,
    const std::vector<InlineFrame>& inline_frames) {

    if (!inline_frames.empty()) {
        bool first = true;
        for (auto it = inline_frames.rbegin(); it != inline_frames.rend(); ++it) {
            if (!first) {
                std::cout << " (inlined by) ";
            }
            first = false;
            PrintFrameLocation(it->name, it->source_file, it->line);
            std::cout << std::endl;
        }

        if (function != nullptr) {
            std::cout << " (inlined by) ";
            PrintFrameLocation(
                function->name,
                entry ? entry->source_file : nullptr,
                entry ? entry->line_start : 0);
            std::cout << std::endl;
        }
        return;
    }

    if (function != nullptr) {
        PrintFrameLocation(function->name, entry ? entry->source_file : nullptr, entry ? entry->line_start : 0);
        std::cout << std::endl;
        return;
    }

    if (entry != nullptr) {
        std::cout
            << entry->source_file
            << ':'
            << entry->line_start;

        if (entry->line_end > entry->line_start) {
            std::cout << '-' << entry->line_end;
        }

        std::cout << std::endl;
        return;
    }

    std::cout << original << " -> <not found>" << std::endl;
}

}  // namespace

int main(int argc, char** argv) {
    CommandLine command_line;
    std::string error;
    if (!ParseCommandLine(argc, argv, command_line, error)) {
        std::cerr << error << "\n\n" << Usage();
        return 1;
    }

    Resolver resolver;
    if (!resolver.Load(command_line.pdb_path, error)) {
        std::cerr << error << '\n';
        return 2;
    }

    MemoryMappedFile image_file;
    if (!command_line.image_path.empty() && !image_file.Open(command_line.image_path.c_str(), error)) {
        std::cerr << "cannot open image: " << error << '\n';
        return 3;
    }

    struct ResolvedQuery {
        std::string original;
        std::uint32_t rva = 0;
    };
    std::vector<ResolvedQuery> queries;
    queries.reserve(command_line.query_values.size());
    for (const std::string& value : command_line.query_values) {
        error.clear();
        std::optional<std::uint32_t> rva =
            resolver.MakeQuery(command_line.query_kind, value, image_file.IsOpen() ? &image_file : nullptr, command_line.image_base_override, error);
        if (!rva) {
            std::cerr << error << '\n';
            return 4;
        }
        queries.push_back({ value, *rva });
    }

    std::vector<std::uint32_t> target_rvas;
    target_rvas.reserve(queries.size());
    for (const auto& q : queries) {
        target_rvas.push_back(q.rva);
    }
    resolver.SetTargetRvas(std::move(target_rvas));

    for (const auto& q : queries) {
        error.clear();
        const FunctionEntry* function = resolver.LoadModulesForRva(q.rva, error);
        if (!error.empty()) {
            std::cerr << error << '\n';
            return 2;
        }

        PrintResult(
            q.original,
            resolver.Find(q.rva),
            function,
            resolver.FindInlineFrames(function, q.rva));
    }

    return 0;
}
