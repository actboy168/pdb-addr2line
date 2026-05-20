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
        "  pdb-addr2line <pdb-path> <rva> [more-rva...]\n"
        "  pdb-addr2line <pdb-path> --rva <rva> [more-rva...]\n"
        "  pdb-addr2line <pdb-path> --va <virtual-address> [more-virtual-address...]\n"
        "  pdb-addr2line <pdb-path> --image <binary-path> --va <virtual-address> [more-virtual-address...]\n"
        "  pdb-addr2line <pdb-path> --image-base <hex> --va <virtual-address> [more-virtual-address...]\n";
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

        if (arg == "--rva" || arg == "--va") {
            if (i + 1 >= argc) {
                error = arg + " requires at least one value";
                return false;
            }

            if (arg == "--rva") {
                command_line.query_kind = QueryKind::Rva;
            } else if (arg == "--va") {
                command_line.query_kind = QueryKind::Va;
            }

            for (++i; i < argc; ++i) {
                const std::string value_arg = argv[i];
                command_line.query_values.emplace_back(value_arg);
            }
            break;
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
    if (command_line.query_kind == QueryKind::Va &&
        command_line.image_path.empty() &&
        command_line.image_base_override == 0) {
        error = "--va requires --image <binary-path> or --image-base <hex>";
        return false;
    }

    return true;
}

void PrintFrameLocation(
    const Resolver& resolver,
    std::uint32_t name_index,
    bool has_source,
    std::uint32_t source_index,
    std::uint32_t line) {
    std::cout << resolver.GetString(name_index);
    if (has_source) {
        std::cout << " at " << resolver.GetString(source_index) << ':' << line;
    }
}

void PrintResult(
    const Query& query,
    const Resolver& resolver,
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
            PrintFrameLocation(resolver, it->name_index, it->has_source, it->source_index, it->line);
            std::cout << std::endl;
        }

        if (function != nullptr) {
            std::cout << " (inlined by) ";
            PrintFrameLocation(
                resolver,
                function->name_index,
                entry != nullptr,
                entry != nullptr ? entry->source_index : 0,
                entry != nullptr ? entry->line_start : 0);
            std::cout << std::endl;
        }
        return;
    }

    if (function != nullptr) {
        PrintFrameLocation(resolver, function->name_index, entry != nullptr, entry != nullptr ? entry->source_index : 0, entry != nullptr ? entry->line_start : 0);
        std::cout << std::endl;
        return;
    }

    if (entry != nullptr) {
        std::cout
            << resolver.GetString(entry->source_index)
            << ':'
            << entry->line_start;

        if (entry->line_end > entry->line_start) {
            std::cout << '-' << entry->line_end;
        }

        std::cout << std::endl;
        return;
    }

    std::cout << query.original << " -> <not found>" << std::endl;
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

    for (const std::string& value : command_line.query_values) {
        error.clear();
        const std::optional<Query> query =
            resolver.MakeQuery(command_line.query_kind, value, image_file.IsOpen() ? &image_file : nullptr, command_line.image_base_override, error);
        if (!query) {
            std::cerr << error << '\n';
            return 4;
        }

        if (!resolver.LoadModulesForRva(query->rva, error)) {
            std::cerr << error << '\n';
            return 2;
        }

        PrintResult(
            *query,
            resolver,
            resolver.Find(query->rva),
            resolver.FindFunction(query->rva),
            resolver.FindInlineFrames(query->rva));
    }

    return 0;
}
