#pragma once

#include "types.h"
#include "memory_mapped_file.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_NamesStream.h"

#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace PDB {
    class RawFile;
    class InfoStream;
    class DBIStream;
    class IPIStream;
    class TPIStream;
}

class Resolver {
public:
    Resolver();
    ~Resolver();

    bool Load(const std::string& pdb_path, std::string& error);
    bool LoadModulesForRva(std::uint32_t rva, std::string& error);

    std::optional<Query> MakeQuery(
        QueryKind kind,
        const std::string& value,
        MemoryMappedFile* image_file,
        std::uint64_t image_base_override,
        std::string& error) const;

    const LineEntry* Find(std::uint32_t rva) const;
    const FunctionEntry* FindFunction(std::uint32_t rva) const;
    std::vector<InlineFrame> FindInlineFrames(std::uint32_t rva);

private:
    void ProcessModules(
        const PDB::ModuleInfoStream& module_info_stream,
        const PDB::NamesStream& names_stream,
        const std::unordered_set<std::uint32_t>* module_filter,
        std::string& error);

    void ResetLoadedState();
    void ResetTypeResolutionState();
    bool TryGetInlineFrame(
        const InlineSiteEntry& site,
        std::uint32_t offset_in_function,
        InlineFrame& frame);

    bool FindInlineFramesRecursive(
        const std::vector<std::size_t>& candidates,
        std::uint32_t offset_in_function,
        std::vector<InlineFrame>& frames);

    void StoreFunction(
        std::unordered_map<std::uint32_t, std::size_t>& function_index_by_rva,
        std::uint32_t rva,
        std::uint32_t code_size,
        const char* name);

    std::vector<std::uint32_t> FindModuleIndicesForRva(std::uint32_t rva) const;
    bool EnsureIpiStream();
    bool EnsureTpiStream();
    void BuildTpiRecordOffsets();
    const char* ResolveInlineeNameIndex(std::uint32_t inlinee_id);
    const char* ResolveClassTypeNameIndex(std::uint32_t type_index);
    void ResolveInlineSiteName(InlineSiteEntry& site);
    void LoadPublicSymbols();
    bool TryLoadPublicFunction(std::uint32_t rva);

    MemoryMappedFile pdb_file_;
    const void* pdb_data_ = nullptr;
    std::unique_ptr<PDB::RawFile> raw_file_;
    std::unique_ptr<PDB::InfoStream> info_stream_;
    std::unique_ptr<PDB::DBIStream> dbi_stream_;
    std::unique_ptr<PDB::IPIStream> ipi_stream_;
    std::unique_ptr<PDB::TPIStream> tpi_stream_;
    PDB::ImageSectionStream image_sections_;
    PDB::ModuleInfoStream module_info_stream_;
    PDB::NamesStream names_stream_;
    bool has_public_symbol_stream_ = false;
    bool all_modules_loaded_ = false;
    bool public_symbols_loaded_ = false;
    bool ipi_stream_checked_ = false;
    bool tpi_stream_checked_ = false;

    std::unordered_map<std::uint32_t, const char*> inlinee_name_by_id_;
    std::unordered_map<std::uint32_t, const char*> class_type_name_by_id_;
    std::unordered_set<std::uint32_t> missing_inlinee_ids_;
    std::unordered_set<std::uint32_t> missing_class_type_ids_;
    std::unordered_set<std::uint32_t> resolving_inlinee_ids_;
    std::unordered_set<std::uint32_t> loaded_module_indices_;
    std::vector<std::size_t> tpi_record_offsets_;

    std::deque<std::string> owned_strings_;
    std::vector<LineEntry> lines_;
    std::vector<FunctionEntry> functions_;
    std::vector<InlineSiteEntry> inline_sites_;
    std::unordered_map<std::uint32_t, std::vector<std::size_t>> inline_roots_by_function_rva_;

    std::vector<std::pair<std::uint32_t, std::uint32_t>> contribution_rvas_;
    std::vector<std::uint16_t> contribution_modules_;
};
