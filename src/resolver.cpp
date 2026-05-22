#include "resolver.h"
#include "binary_annotations.h"
#include "pe_utils.h"
#include "utils.h"

#include "Foundation/PDB_PointerUtil.h"
#include "PDB.h"
#include "PDB_DBIStream.h"
#include "PDB_DBITypes.h"
#include "PDB_IPIStream.h"
#include "PDB_InfoStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleLineStream.h"
#include "PDB_ModuleSymbolStream.h"
#include "PDB_NamesStream.h"
#include "PDB_PublicSymbolStream.h"
#include "PDB_RawFile.h"
#include "PDB_SectionContributionStream.h"
#include "PDB_TPIStream.h"
#include "PDB_Util.h"

#include <algorithm>
#include <string_view>

Resolver::Resolver() = default;
Resolver::~Resolver() = default;

namespace {

constexpr std::uint32_t kInvalidStringIndex = std::numeric_limits<std::uint32_t>::max();

std::string ErrorCodeToString(PDB::ErrorCode code) {
    switch (code) {
    case PDB::ErrorCode::Success:
        return "success";
    case PDB::ErrorCode::InvalidDataSize:
        return "invalid data size";
    case PDB::ErrorCode::InvalidSuperBlock:
        return "invalid super block";
    case PDB::ErrorCode::InvalidFreeBlockMap:
        return "invalid free block map";
    case PDB::ErrorCode::InvalidStream:
        return "invalid stream";
    case PDB::ErrorCode::InvalidSignature:
        return "invalid stream signature";
    case PDB::ErrorCode::InvalidStreamIndex:
        return "invalid stream index";
    case PDB::ErrorCode::UnknownVersion:
        return "unknown version";
    default:
        return "unknown error";
    }
}

std::string_view TrimTrailingNul(std::string_view value) {
    while (!value.empty() && value.back() == '\0') {
        value.remove_suffix(1);
    }
    return value;
}

std::string_view ToStringView(PDB::ArrayView<char> view) {
    return TrimTrailingNul(std::string_view(view.Decay(), view.GetLength()));
}

std::uint8_t GetNumericLeafSize(PDB::CodeView::TPI::TypeRecordKind kind) {
    using TypeKind = PDB::CodeView::TPI::TypeRecordKind;

    if (kind < TypeKind::LF_NUMERIC) {
        return sizeof(TypeKind);
    }

    switch (kind) {
    case TypeKind::LF_CHAR:
        return sizeof(TypeKind) + sizeof(std::uint8_t);
    case TypeKind::LF_USHORT:
    case TypeKind::LF_SHORT:
        return sizeof(TypeKind) + sizeof(std::uint16_t);
    case TypeKind::LF_LONG:
    case TypeKind::LF_ULONG:
        return sizeof(TypeKind) + sizeof(std::uint32_t);
    case TypeKind::LF_QUADWORD:
    case TypeKind::LF_UQUADWORD:
        return sizeof(TypeKind) + sizeof(std::uint64_t);
    default:
        return 0;
    }
}

const char* GetLeafName(const char* data, PDB::CodeView::TPI::TypeRecordKind kind) {
    const std::uint8_t size = GetNumericLeafSize(kind);
    return size != 0 ? data + size : nullptr;
}

}  // namespace

void Resolver::ResetLoadedState() {
    strings_.Clear();
    lines_.clear();
    functions_.clear();
    inline_sites_.clear();
    inline_roots_by_function_rva_.clear();
    pending_file_indices_.clear();
    contribution_rvas_.clear();
    contribution_modules_.clear();
    loaded_module_indices_.clear();
    all_modules_loaded_ = false;
    public_symbols_loaded_ = false;
}

void Resolver::ResetTypeResolutionState() {
    inlinee_name_index_by_id_.clear();
    class_type_name_index_by_id_.clear();
    missing_inlinee_ids_.clear();
    missing_class_type_ids_.clear();
    resolving_inlinee_ids_.clear();
    ipi_stream_.reset();
    tpi_stream_.reset();
    ipi_stream_checked_ = false;
    tpi_stream_checked_ = false;
    unknown_inlinee_name_index_ = kInvalidStringIndex;
    tpi_record_offsets_.clear();
}

bool Resolver::Load(const std::string& pdb_path, std::string& error) {
    if (!pdb_file_.Open(pdb_path.c_str(), error)) {
        error = "cannot open PDB: " + error;
        return false;
    }

    pdb_data_ = pdb_file_.Data();
    const PDB::ErrorCode validate = PDB::ValidateFile(pdb_data_, pdb_file_.Size());
    if (validate != PDB::ErrorCode::Success) {
        error = "invalid PDB: " + ErrorCodeToString(validate);
        return false;
    }

    raw_file_ = std::make_unique<PDB::RawFile>(PDB::CreateRawFile(pdb_data_));
    const PDB::ErrorCode has_dbi = PDB::HasValidDBIStream(*raw_file_);
    if (has_dbi != PDB::ErrorCode::Success) {
        error = "PDB DBI stream is invalid: " + ErrorCodeToString(has_dbi);
        return false;
    }

    info_stream_ = std::make_unique<PDB::InfoStream>(*raw_file_);
    if (info_stream_->UsesDebugFastLink()) {
        error = "PDB was linked with unsupported /DEBUG:FASTLINK";
        return false;
    }
    if (!info_stream_->HasNamesStream()) {
        error = "PDB has no /names stream";
        return false;
    }

    dbi_stream_ = std::make_unique<PDB::DBIStream>(PDB::CreateDBIStream(*raw_file_));
    if (dbi_stream_->HasValidImageSectionStream(*raw_file_) != PDB::ErrorCode::Success) {
        error = "PDB image section stream is invalid";
        return false;
    }

    image_sections_ = dbi_stream_->CreateImageSectionStream(*raw_file_);
    module_info_stream_ = dbi_stream_->CreateModuleInfoStream(*raw_file_);
    names_stream_ = info_stream_->CreateNamesStream(*raw_file_);
    has_public_symbol_stream_ =
        dbi_stream_->HasValidPublicSymbolStream(*raw_file_) == PDB::ErrorCode::Success;

    ResetLoadedState();
    ResetTypeResolutionState();

    // Load section contributions for module filtering
    if (dbi_stream_->HasValidSectionContributionStream(*raw_file_) == PDB::ErrorCode::Success) {
        const PDB::SectionContributionStream scs = dbi_stream_->CreateSectionContributionStream(*raw_file_);
        const size_t contrib_count = scs.GetContributions().GetLength();
        contribution_rvas_.reserve(contrib_count);
        contribution_modules_.reserve(contrib_count);
        for (const PDB::DBI::SectionContribution& sc : scs.GetContributions()) {
            const std::uint32_t rva = image_sections_.ConvertSectionOffsetToRVA(sc.section, sc.offset);
            if (rva == 0 && sc.offset != 0) {
                continue;
            }
            contribution_rvas_.push_back({ rva, sc.size });
            contribution_modules_.push_back(sc.moduleIndex);
        }
    }

    return true;
}

std::vector<std::uint32_t> Resolver::FindModuleIndicesForRva(std::uint32_t rva) const {
    std::vector<std::uint32_t> result;
    for (std::size_t i = 0; i < contribution_rvas_.size(); ++i) {
        const std::uint32_t start = contribution_rvas_[i].first;
        const std::uint32_t end = start + contribution_rvas_[i].second;
        if (rva >= start && rva < end) {
            result.push_back(contribution_modules_[i]);
        }
    }
    return result;
}

void Resolver::ProcessModules(
    const PDB::ModuleInfoStream& module_info_stream,
    const PDB::NamesStream& names_stream,
    const std::unordered_set<std::uint32_t>* module_filter,
    std::string& error) {
    std::vector<PendingFilename> filenames;
    std::unordered_map<std::uint32_t, std::size_t> function_index_by_rva;
    const std::size_t new_lines_start = lines_.size();

    std::vector<std::uint32_t> modules_to_process;
    if (module_filter != nullptr) {
        modules_to_process.assign(module_filter->begin(), module_filter->end());
    } else {
        const size_t count = module_info_stream.GetModules().GetLength();
        modules_to_process.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            modules_to_process.push_back(i);
        }
    }

    for (std::uint32_t module_index : modules_to_process) {
        const PDB::ModuleInfoStream::Module& module = module_info_stream.GetModule(module_index);

        std::unordered_map<std::uint32_t, InlineeSourceInfo> module_inlinee_sources;
        std::unordered_map<std::uint32_t, std::uint32_t> module_filename_offset_by_checksum_offset;
        const auto resolve_module_source_index = [&](std::uint32_t file_checksum_offset) -> std::optional<std::uint32_t> {
            const auto it = module_filename_offset_by_checksum_offset.find(file_checksum_offset);
            if (it == module_filename_offset_by_checksum_offset.end()) {
                return std::nullopt;
            }
            return strings_.Intern(names_stream.GetFilename(it->second));
        };

        if (!module.HasLineStream()) {
            if (!module.HasSymbolStream()) {
                continue;
            }
        } else {
            struct PendingInlineeSource {
                std::uint32_t inlinee_id = 0;
                std::uint32_t file_checksum_offset = 0;
                std::uint32_t line_start = 0;
            };

            const PDB::ModuleLineStream module_line_stream = module.CreateLineStream(*raw_file_);

            const std::size_t module_filenames_start = filenames.size();
            std::vector<PendingInlineeSource> pending_inlinee_sources;

            module_line_stream.ForEachSection(
                [&](const PDB::CodeView::DBI::LineSection* section) {
                    if (section->header.kind == PDB::CodeView::DBI::DebugSubsectionKind::S_FILECHECKSUMS) {
                        const auto* checksum_base = reinterpret_cast<const std::uint8_t*>(&section->checksumHeader);
                        module_line_stream.ForEachFileChecksum(
                            section,
                            [&](const PDB::CodeView::DBI::FileChecksumHeader* checksum_header) {
                                const auto* checksum_bytes = reinterpret_cast<const std::uint8_t*>(checksum_header);
                                const std::uint32_t checksum_offset =
                                    static_cast<std::uint32_t>(checksum_bytes - checksum_base);
                                module_filename_offset_by_checksum_offset.emplace(
                                    checksum_offset,
                                    checksum_header->filenameOffset);
                            });
                        return;
                    }

                    if (section->header.kind == PDB::CodeView::DBI::DebugSubsectionKind::S_LINES) {
                        module_line_stream.ForEachLinesBlock(
                            section,
                            [&](const PDB::CodeView::DBI::LinesFileBlockHeader* lines_block_header,
                                const PDB::CodeView::DBI::Line* block_lines,
                                const PDB::CodeView::DBI::Column*) {
                                if (lines_block_header->numLines == 0) {
                                    return;
                                }

                                const std::size_t filename_index = filenames.size();
                                filenames.push_back({ lines_block_header->fileChecksumOffset, 0 });

                                const std::uint16_t section_index = section->linesHeader.sectionIndex;
                                const std::uint32_t section_base_offset = section->linesHeader.sectionOffset;

                                for (std::uint32_t i = 0; i < lines_block_header->numLines; ++i) {
                                    const PDB::CodeView::DBI::Line& current = block_lines[i];
                                    const std::uint32_t code_size =
                                        (i + 1 < lines_block_header->numLines)
                                        ? (block_lines[i + 1].offset - current.offset)
                                        : (section->linesHeader.codeSize - current.offset);

                                    const std::uint32_t section_offset = section_base_offset + current.offset;
                                    const std::uint32_t rva = image_sections_.ConvertSectionOffsetToRVA(section_index, section_offset);

                                    lines_.push_back({
                                        rva,
                                        code_size,
                                        section_offset,
                                        current.linenumStart,
                                        current.linenumStart + current.deltaLineEnd,
                                        section_index,
                                        0,
                                    });
                                    pending_file_indices_.push_back(filename_index);
                                }
                            });
                        return;
                    }

                    if (section->header.kind != PDB::CodeView::DBI::DebugSubsectionKind::S_INLINEELINES) {
                        return;
                    }

                    if (section->inlineeHeader.kind == PDB::CodeView::DBI::InlineeSourceLineKind::Signature) {
                        module_line_stream.ForEachInlineeSourceLine(
                            section,
                            [&](const PDB::CodeView::DBI::InlineeSourceLine* inlinee_source_line) {
                                pending_inlinee_sources.push_back({
                                    inlinee_source_line->inlinee,
                                    inlinee_source_line->fileChecksumOffset,
                                    inlinee_source_line->lineNumber
                                });
                            });
                        return;
                    }

                    module_line_stream.ForEachInlineeSourceLineEx(
                        section,
                        [&](const PDB::CodeView::DBI::InlineeSourceLineEx* inlinee_source_line_ex) {
                            pending_inlinee_sources.push_back({
                                inlinee_source_line_ex->inlinee,
                                inlinee_source_line_ex->fileChecksumOffset,
                                inlinee_source_line_ex->lineNumber
                            });
                        });
                });

            if ((module_filenames_start != filenames.size() || !pending_inlinee_sources.empty()) &&
                module_filename_offset_by_checksum_offset.empty()) {
                error = "module line data is missing file checksum records";
                return;
            }

            for (std::size_t i = module_filenames_start; i < filenames.size(); ++i) {
                PendingFilename& filename = filenames[i];
                const auto it = module_filename_offset_by_checksum_offset.find(filename.file_checksum_offset);
                if (it == module_filename_offset_by_checksum_offset.end()) {
                    error = "module line data contains invalid file checksum offset";
                    return;
                }
                filename.names_filename_offset = it->second;
            }

            for (const PendingInlineeSource& pending_inlinee : pending_inlinee_sources) {
                InlineeSourceInfo& source = module_inlinee_sources[pending_inlinee.inlinee_id];
                if (source.has_source) {
                    continue;
                }
                if (const std::optional<std::uint32_t> source_index = resolve_module_source_index(pending_inlinee.file_checksum_offset)) {
                    source.source_index = *source_index;
                    source.line_start = pending_inlinee.line_start;
                    source.has_source = true;
                }
            }
        }

        if (module.HasSymbolStream()) {
            const PDB::ModuleSymbolStream module_symbol_stream = module.CreateSymbolStream(*raw_file_);
            std::vector<ScopeEntry> scope_stack;
            std::uint32_t current_function_rva = 0;

            module_symbol_stream.ForEachSymbol(
                [&](const PDB::CodeView::DBI::Record* record) {
                    const auto start_function_scope = [&](const char* name, std::uint16_t section, std::uint32_t offset, std::uint32_t code_size) {
                        const std::uint32_t rva = image_sections_.ConvertSectionOffsetToRVA(section, offset);
                        if (name == nullptr || rva == 0) {
                            return;
                        }

                        const std::uint32_t name_index = strings_.Intern(name);
                        StoreFunction(
                            function_index_by_rva,
                            rva,
                            code_size,
                            name_index);

                        current_function_rva = rva;
                        scope_stack.push_back({ ScopeKind::Function, 0 });
                    };

                    switch (record->header.kind) {
                    case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32:
                        start_function_scope(record->data.S_LPROC32.name, record->data.S_LPROC32.section, record->data.S_LPROC32.offset, record->data.S_LPROC32.codeSize);
                        return;

                    case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32:
                        start_function_scope(record->data.S_GPROC32.name, record->data.S_GPROC32.section, record->data.S_GPROC32.offset, record->data.S_GPROC32.codeSize);
                        return;

                    case PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID:
                        start_function_scope(record->data.S_LPROC32_ID.name, record->data.S_LPROC32_ID.section, record->data.S_LPROC32_ID.offset, record->data.S_LPROC32_ID.codeSize);
                        return;

                    case PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID:
                        start_function_scope(record->data.S_GPROC32_ID.name, record->data.S_GPROC32_ID.section, record->data.S_GPROC32_ID.offset, record->data.S_GPROC32_ID.codeSize);
                        return;

                    case PDB::CodeView::DBI::SymbolRecordKind::S_BLOCK32:
                    case PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32:
                        if (current_function_rva != 0) {
                            scope_stack.push_back({ ScopeKind::Other, 0 });
                        }
                        return;

                    case PDB::CodeView::DBI::SymbolRecordKind::S_INLINESITE: {
                        if (current_function_rva == 0) {
                            return;
                        }

                        const auto inlinee_name_it = inlinee_name_index_by_id_.find(record->data.S_INLINESITE.inlinee);
                        InlineeSourceInfo base_source;
                        if (const auto source_it = module_inlinee_sources.find(record->data.S_INLINESITE.inlinee);
                            source_it != module_inlinee_sources.end()) {
                            base_source = source_it->second;
                        }

                        const std::uint32_t record_size = PDB::GetCodeViewRecordSize(record);
                        const std::uint32_t fixed_size =
                            sizeof(record->data.S_INLINESITE.parent) +
                            sizeof(record->data.S_INLINESITE.end) +
                            sizeof(record->data.S_INLINESITE.inlinee);
                        const std::uint32_t annotation_size = record_size >= fixed_size ? (record_size - fixed_size) : 0;

                        InlineSiteEntry site;
                        site.function_rva = current_function_rva;
                        site.inlinee_id = record->data.S_INLINESITE.inlinee;
                        if (inlinee_name_it != inlinee_name_index_by_id_.end()) {
                            site.name_index = inlinee_name_it->second;
                            site.name_resolved = true;
                        }
                        site.base_source = base_source;
                        site.ranges = BuildInlineRanges(
                            reinterpret_cast<const std::uint8_t*>(record->data.S_INLINESITE.binaryAnnotations),
                            annotation_size,
                            base_source,
                            resolve_module_source_index);

                        const std::size_t inline_site_index = inline_sites_.size();
                        inline_sites_.push_back(std::move(site));

                        bool attached = false;
                        for (auto it = scope_stack.rbegin(); it != scope_stack.rend(); ++it) {
                            if (it->kind != ScopeKind::InlineSite) {
                                continue;
                            }

                            inline_sites_[it->inline_index].children.push_back(inline_site_index);
                            attached = true;
                            break;
                        }

                        if (!attached) {
                            inline_roots_by_function_rva_[current_function_rva].push_back(inline_site_index);
                        }

                        scope_stack.push_back({ ScopeKind::InlineSite, inline_site_index });
                        return;
                    }

                    case PDB::CodeView::DBI::SymbolRecordKind::S_END:
                    case PDB::CodeView::DBI::SymbolRecordKind::S_INLINESITE_END:
                    case PDB::CodeView::DBI::SymbolRecordKind::S_PROC_ID_END:
                        if (scope_stack.empty()) {
                            return;
                        }

                        if (scope_stack.back().kind == ScopeKind::Function) {
                            current_function_rva = 0;
                        }
                        scope_stack.pop_back();
                        return;

                    default:
                        return;
                    }
                });
        }
    }

    for (std::size_t i = 0; i < pending_file_indices_.size(); ++i) {
        const PendingFilename& filename = filenames[pending_file_indices_[i]];
        lines_[new_lines_start + i].source_index =
            strings_.Intern(names_stream.GetFilename(filename.names_filename_offset));
    }
    pending_file_indices_.clear();

    std::sort(lines_.begin(), lines_.end(), [](const LineEntry& lhs, const LineEntry& rhs) {
        if (lhs.rva != rhs.rva) {
            return lhs.rva < rhs.rva;
        }
        if (lhs.section_index != rhs.section_index) {
            return lhs.section_index < rhs.section_index;
        }
        return lhs.section_offset < rhs.section_offset;
    });
    std::sort(functions_.begin(), functions_.end(), [](const FunctionEntry& lhs, const FunctionEntry& rhs) {
        return lhs.rva < rhs.rva;
    });
    for (std::size_t i = 0; i + 1 < functions_.size(); ++i) {
        FunctionEntry& current = functions_[i];
        if (current.code_size != 0) {
            continue;
        }
        const FunctionEntry& next = functions_[i + 1];
        if (next.rva > current.rva) {
            current.code_size = next.rva - current.rva;
        }
    }
}

void Resolver::LoadPublicSymbols() {
    if (public_symbols_loaded_) {
        return;
    }
    public_symbols_loaded_ = true;

    const bool has_symbol_record_stream =
        dbi_stream_->HasValidSymbolRecordStream(*raw_file_) == PDB::ErrorCode::Success;
    if (!has_symbol_record_stream || !has_public_symbol_stream_) {
        return;
    }

    std::unordered_map<std::uint32_t, std::size_t> function_index_by_rva;
    const auto symbol_record_stream = dbi_stream_->CreateSymbolRecordStream(*raw_file_);
    const auto public_symbol_stream = dbi_stream_->CreatePublicSymbolStream(*raw_file_);
    for (const PDB::HashRecord& hash_record : public_symbol_stream.GetRecords()) {
        const PDB::CodeView::DBI::Record* record = public_symbol_stream.GetRecord(symbol_record_stream, hash_record);
        if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32) {
            continue;
        }
        if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
            PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u) {
            continue;
        }

        const std::uint32_t rva =
            image_sections_.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
        if (rva == 0) {
            continue;
        }

        // Reuse existing function index map or build new
        auto [it, inserted] = function_index_by_rva.emplace(rva, functions_.size());
        if (inserted) {
            functions_.push_back({ rva, 0, strings_.Intern(record->data.S_PUB32.name) });
        }
    }

    if (!functions_.empty()) {
        std::sort(functions_.begin(), functions_.end(), [](const FunctionEntry& lhs, const FunctionEntry& rhs) {
            return lhs.rva < rhs.rva;
        });
        for (std::size_t i = 0; i + 1 < functions_.size(); ++i) {
            FunctionEntry& current = functions_[i];
            if (current.code_size != 0) {
                continue;
            }
            const FunctionEntry& next = functions_[i + 1];
            if (next.rva > current.rva) {
                current.code_size = next.rva - current.rva;
            }
        }
    }
}

bool Resolver::EnsureIpiStream() {
    if (ipi_stream_checked_) {
        return ipi_stream_ != nullptr;
    }

    ipi_stream_checked_ = true;
    if (!(info_stream_->HasIPIStream() && PDB::HasValidIPIStream(*raw_file_) == PDB::ErrorCode::Success)) {
        return false;
    }

    ipi_stream_ = std::make_unique<PDB::IPIStream>(PDB::CreateIPIStream(*raw_file_));
    return true;
}

bool Resolver::EnsureTpiStream() {
    if (tpi_stream_checked_) {
        return tpi_stream_ != nullptr;
    }

    tpi_stream_checked_ = true;
    if (PDB::HasValidTPIStream(*raw_file_) != PDB::ErrorCode::Success) {
        return false;
    }

    tpi_stream_ = std::make_unique<PDB::TPIStream>(PDB::CreateTPIStream(*raw_file_));
    return true;
}

void Resolver::BuildTpiRecordOffsets() {
    if (!tpi_record_offsets_.empty() || !EnsureTpiStream()) {
        return;
    }

    tpi_record_offsets_.resize(tpi_stream_->GetTypeRecordCount());
    const std::uint32_t first_type_index = tpi_stream_->GetFirstTypeIndex();
    std::uint32_t type_index = first_type_index;
    tpi_stream_->ForEachTypeRecordHeaderAndOffset(
        [&](const PDB::CodeView::TPI::RecordHeader&, std::size_t offset) {
            tpi_record_offsets_[type_index - first_type_index] = offset;
            ++type_index;
        });
}

std::optional<std::uint32_t> Resolver::ResolveClassTypeNameIndex(std::uint32_t type_index) {
    if (const auto it = class_type_name_index_by_id_.find(type_index); it != class_type_name_index_by_id_.end()) {
        return it->second;
    }
    if (missing_class_type_ids_.count(type_index) != 0 || !EnsureTpiStream()) {
        return std::nullopt;
    }

    const std::uint32_t first_type_index = tpi_stream_->GetFirstTypeIndex();
    const std::uint32_t last_type_index = tpi_stream_->GetLastTypeIndex();
    if (type_index < first_type_index || type_index >= last_type_index) {
        missing_class_type_ids_.insert(type_index);
        return std::nullopt;
    }

    BuildTpiRecordOffsets();
    const std::size_t offset = tpi_record_offsets_[type_index - first_type_index];
    const PDB::CodeView::TPI::RecordHeader header = tpi_stream_->ReadTypeRecordHeader(offset);
    const std::size_t total_size = sizeof(std::uint16_t) + header.size;
    std::vector<std::uint8_t> record_bytes(total_size);
    const PDB::DirectMSFStream& tpi_data = tpi_stream_->GetDirectMSFStream();
    tpi_data.ReadAtOffset(record_bytes.data(), total_size, offset);

    const auto* record = reinterpret_cast<const PDB::CodeView::TPI::Record*>(record_bytes.data());
    const char* name = nullptr;
    switch (header.kind) {
    case PDB::CodeView::TPI::TypeRecordKind::LF_CLASS:
    case PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE:
        name = GetLeafName(record->data.LF_CLASS.data, record->data.LF_CLASS.lfEasy.kind);
        break;
    case PDB::CodeView::TPI::TypeRecordKind::LF_CLASS2:
    case PDB::CodeView::TPI::TypeRecordKind::LF_STRUCTURE2:
        name = GetLeafName(record->data.LF_CLASS2.data, record->data.LF_CLASS2.lfEasy.kind);
        break;
    case PDB::CodeView::TPI::TypeRecordKind::LF_UNION: {
        const auto kind = *reinterpret_cast<const PDB::CodeView::TPI::TypeRecordKind*>(record->data.LF_UNION.data);
        name = GetLeafName(record->data.LF_UNION.data, kind);
        break;
    }
    case PDB::CodeView::TPI::TypeRecordKind::LF_ENUM:
        name = record->data.LF_ENUM.name;
        break;
    default:
        break;
    }

    if (name == nullptr || name[0] == '\0') {
        missing_class_type_ids_.insert(type_index);
        return std::nullopt;
    }

    const std::uint32_t name_index = strings_.Intern(name);
    class_type_name_index_by_id_.emplace(type_index, name_index);
    return name_index;
}

std::optional<std::uint32_t> Resolver::ResolveInlineeNameIndex(std::uint32_t inlinee_id) {
    if (const auto it = inlinee_name_index_by_id_.find(inlinee_id); it != inlinee_name_index_by_id_.end()) {
        return it->second;
    }
    if (missing_inlinee_ids_.count(inlinee_id) != 0 || !EnsureIpiStream()) {
        return std::nullopt;
    }

    const std::uint32_t first_type_index = ipi_stream_->GetFirstTypeIndex();
    const std::uint32_t last_type_index = ipi_stream_->GetLastTypeIndex();
    if (inlinee_id < first_type_index || inlinee_id >= last_type_index) {
        missing_inlinee_ids_.insert(inlinee_id);
        return std::nullopt;
    }

    const auto ipi_records = ipi_stream_->GetTypeRecords();
    const PDB::CodeView::IPI::Record* record = ipi_records[inlinee_id - first_type_index];
    std::string qualified_name;

    switch (record->header.kind) {
    case PDB::CodeView::IPI::TypeRecordKind::LF_FUNC_ID: {
        const bool inserted = resolving_inlinee_ids_.insert(inlinee_id).second;
        if (!inserted) {
            qualified_name = record->data.LF_FUNC_ID.name;
            break;
        }

        if (record->data.LF_FUNC_ID.scopeId != 0) {
            if (const std::optional<std::uint32_t> parent_name_index =
                ResolveInlineeNameIndex(record->data.LF_FUNC_ID.scopeId)) {
                qualified_name += GetString(*parent_name_index);
                qualified_name += "::";
            }
        }
        qualified_name += record->data.LF_FUNC_ID.name;
        resolving_inlinee_ids_.erase(inlinee_id);
        break;
    }

    case PDB::CodeView::IPI::TypeRecordKind::LF_MFUNC_ID: {
        const bool inserted = resolving_inlinee_ids_.insert(inlinee_id).second;
        if (!inserted) {
            qualified_name = record->data.LF_MFUNC_ID.name;
            break;
        }

        if (const std::optional<std::uint32_t> class_name_index =
            ResolveClassTypeNameIndex(record->data.LF_MFUNC_ID.parentTypeIndex)) {
            qualified_name += GetString(*class_name_index);
            qualified_name += "::";
        }
        qualified_name += record->data.LF_MFUNC_ID.name;
        resolving_inlinee_ids_.erase(inlinee_id);
        break;
    }

    default:
        missing_inlinee_ids_.insert(inlinee_id);
        return std::nullopt;
    }

    if (qualified_name.empty()) {
        missing_inlinee_ids_.insert(inlinee_id);
        return std::nullopt;
    }

    const std::uint32_t name_index = strings_.Intern(std::move(qualified_name));
    inlinee_name_index_by_id_.emplace(inlinee_id, name_index);
    return name_index;
}

void Resolver::ResolveInlineSiteName(InlineSiteEntry& site) {
    if (site.name_resolved) {
        return;
    }

    if (const std::optional<std::uint32_t> name_index = ResolveInlineeNameIndex(site.inlinee_id)) {
        site.name_index = *name_index;
    } else {
        site.name_index = GetUnknownInlineeNameIndex();
    }
    site.name_resolved = true;
}

bool Resolver::TryLoadPublicFunction(std::uint32_t rva) {
    if (!has_public_symbol_stream_) {
        return false;
    }
    if (dbi_stream_->HasValidSymbolRecordStream(*raw_file_) != PDB::ErrorCode::Success) {
        return false;
    }

    struct Candidate {
        const char* name = nullptr;
        std::uint32_t rva = 0;
        bool found = false;
    };

    const auto symbol_record_stream = dbi_stream_->CreateSymbolRecordStream(*raw_file_);
    const auto public_symbol_stream = dbi_stream_->CreatePublicSymbolStream(*raw_file_);
    Candidate previous;
    std::uint32_t next_rva = 0;
    bool has_next = false;
    for (const PDB::HashRecord& hash_record : public_symbol_stream.GetRecords()) {
        const PDB::CodeView::DBI::Record* record = public_symbol_stream.GetRecord(symbol_record_stream, hash_record);
        if (record->header.kind != PDB::CodeView::DBI::SymbolRecordKind::S_PUB32) {
            continue;
        }
        if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
            PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u) {
            continue;
        }

        const std::uint32_t symbol_rva =
            image_sections_.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
        if (symbol_rva == 0) {
            continue;
        }

        if (symbol_rva <= rva) {
            if (!previous.found || symbol_rva > previous.rva) {
                previous.name = record->data.S_PUB32.name;
                previous.rva = symbol_rva;
                previous.found = true;
            }
            continue;
        }

        if (!has_next || symbol_rva < next_rva) {
            next_rva = symbol_rva;
            has_next = true;
        }
    }

    if (!previous.found) {
        return false;
    }

    const std::uint32_t code_size =
        (has_next && next_rva > previous.rva) ? (next_rva - previous.rva) : (rva - previous.rva + 1u);
    auto it = std::lower_bound(
        functions_.begin(), functions_.end(), previous.rva,
        [](const FunctionEntry& entry, std::uint32_t value) {
            return entry.rva < value;
        });

    const std::uint32_t name_index = strings_.Intern(previous.name);
    if (it == functions_.end() || it->rva != previous.rva) {
        functions_.insert(it, { previous.rva, code_size, name_index });
        return true;
    }

    if (it->code_size == 0 || static_cast<std::uint64_t>(it->rva) + it->code_size <= rva) {
        it->code_size = code_size;
    }
    it->name_index = name_index;
    return true;
}

std::uint32_t Resolver::GetUnknownInlineeNameIndex() {
    if (unknown_inlinee_name_index_ == kInvalidStringIndex) {
        unknown_inlinee_name_index_ = strings_.Intern("<unknown-inlinee>");
    }
    return unknown_inlinee_name_index_;
}

bool Resolver::LoadModulesForRva(std::uint32_t rva, std::string& error) {
    if (all_modules_loaded_) {
        return true;
    }

    std::vector<std::uint32_t> module_indices = FindModuleIndicesForRva(rva);
    if (!module_indices.empty()) {
        module_indices.erase(
            std::remove_if(module_indices.begin(), module_indices.end(),
                [this](std::uint32_t idx) { return loaded_module_indices_.count(idx) != 0; }),
            module_indices.end());
    }

    if (module_indices.empty() && !all_modules_loaded_) {
        if (loaded_module_indices_.empty()) {
            all_modules_loaded_ = true;
            ProcessModules(module_info_stream_, names_stream_, nullptr, error);
        }
    } else if (!module_indices.empty()) {
        std::unordered_set<std::uint32_t> filter(module_indices.begin(), module_indices.end());
        ProcessModules(module_info_stream_, names_stream_, &filter, error);
        for (std::uint32_t idx : module_indices) {
            loaded_module_indices_.insert(idx);
        }
    }

    const FunctionEntry* function = FindFunction(rva);
    if (function == nullptr && !public_symbols_loaded_) {
        if (TryLoadPublicFunction(rva)) {
            function = FindFunction(rva);
        } else {
            LoadPublicSymbols();
            function = FindFunction(rva);
        }
    }

    return error.empty();
}

std::optional<Query> Resolver::MakeQuery(
    QueryKind kind,
    const std::string& value,
    MemoryMappedFile* image_file,
    std::uint64_t image_base_override,
    std::string& error) const {
    Query query;
    query.original = value;

    switch (kind) {
    case QueryKind::Rva: {
        std::uint64_t parsed = 0;
        if (!ParseInteger64(value, parsed)) {
            error = "invalid RVA: " + value;
            return std::nullopt;
        }
        if (parsed > 0xFFFFFFFFull) {
            error = "RVA is out of range: " + value;
            return std::nullopt;
        }
        query.rva = static_cast<std::uint32_t>(parsed);
        return query;
    }

    case QueryKind::Va: {
        std::uint64_t parsed = 0;
        if (!ParseInteger64(value, parsed)) {
            error = "invalid virtual address: " + value;
            return std::nullopt;
        }

        std::uint64_t image_base = 0;
        if (image_base_override != 0) {
            image_base = image_base_override;
        } else if (image_file != nullptr) {
            if (!ReadPeImageBase(image_file->Data(), image_file->Size(), image_base, error)) {
                error = "cannot read image base: " + error;
                return std::nullopt;
            }
        } else {
            error = "virtual address requires --image <binary-path> or --image-base <hex>: " + value;
            return std::nullopt;
        }

        if (parsed < image_base) {
            error = "virtual address is below image base: " + value;
            return std::nullopt;
        }

        const std::uint64_t rva64 = parsed - image_base;
        if (rva64 > 0xFFFFFFFFull) {
            error = "RVA converted from virtual address is out of range: " + value;
            return std::nullopt;
        }

        query.rva = static_cast<std::uint32_t>(rva64);
        return query;
    }
    }

    error = "unsupported query type";
    return std::nullopt;
}

const LineEntry* Resolver::Find(std::uint32_t rva) const {
    const auto it = std::upper_bound(
        lines_.begin(), lines_.end(), rva,
        [](std::uint32_t value, const LineEntry& entry) {
            return value < entry.rva;
        });

    if (it == lines_.begin()) {
        return nullptr;
    }

    const LineEntry& candidate = *std::prev(it);
    const std::uint64_t exclusive_end = static_cast<std::uint64_t>(candidate.rva) + std::max<std::uint32_t>(candidate.code_size, 1u);
    if (rva < exclusive_end) {
        return &candidate;
    }
    return nullptr;
}

const FunctionEntry* Resolver::FindFunction(std::uint32_t rva) const {
    const auto it = std::upper_bound(
        functions_.begin(), functions_.end(), rva,
        [](std::uint32_t value, const FunctionEntry& entry) {
            return value < entry.rva;
        });

    if (it == functions_.begin()) {
        return nullptr;
    }

    const FunctionEntry& candidate = *std::prev(it);
    const std::uint64_t exclusive_end =
        static_cast<std::uint64_t>(candidate.rva) + std::max<std::uint32_t>(candidate.code_size, 1u);
    if (rva < exclusive_end) {
        return &candidate;
    }
    return nullptr;
}

std::vector<InlineFrame> Resolver::FindInlineFrames(std::uint32_t rva) {
    const FunctionEntry* function = FindFunction(rva);
    if (function == nullptr) {
        return {};
    }

    const auto it = inline_roots_by_function_rva_.find(function->rva);
    if (it == inline_roots_by_function_rva_.end()) {
        return {};
    }

    std::vector<InlineFrame> frames;
    const std::uint32_t offset_in_function = rva - function->rva;
    FindInlineFramesRecursive(it->second, offset_in_function, frames);
    return frames;
}

const std::string& Resolver::GetString(std::uint32_t index) const {
    return strings_.Get(index);
}

bool Resolver::TryGetInlineFrame(const InlineSiteEntry& site, std::uint32_t offset_in_function, InlineFrame& frame) {
    for (const InlineRange& range : site.ranges) {
        if (offset_in_function < range.start_offset || offset_in_function >= range.end_offset) {
            continue;
        }

        frame.has_source = range.has_source || site.base_source.has_source;
        if (range.has_source) {
            frame.source_index = range.source_index;
        } else {
            frame.source_index = site.base_source.source_index;
        }

        const std::int64_t line =
            static_cast<std::int64_t>(site.base_source.line_start) + static_cast<std::int64_t>(range.line_offset);
        frame.line = line > 0 ? static_cast<std::uint32_t>(line) : 0;
        return true;
    }

    return false;
}

bool Resolver::FindInlineFramesRecursive(
    const std::vector<std::size_t>& candidates,
    std::uint32_t offset_in_function,
    std::vector<InlineFrame>& frames) {
    for (const std::size_t candidate_index : candidates) {
        InlineSiteEntry& site = inline_sites_[candidate_index];
        InlineFrame frame;
        if (!TryGetInlineFrame(site, offset_in_function, frame)) {
            continue;
        }

        ResolveInlineSiteName(site);
        frame.name_index = site.name_index;
        frames.push_back(frame);
        if (FindInlineFramesRecursive(site.children, offset_in_function, frames)) {
            return true;
        }
        return true;
    }

    return false;
}

void Resolver::StoreFunction(
    std::unordered_map<std::uint32_t, std::size_t>& function_index_by_rva,
    std::uint32_t rva,
    std::uint32_t code_size,
    std::uint32_t name_index) {
    const auto [it, inserted] = function_index_by_rva.emplace(rva, functions_.size());
    if (inserted) {
        functions_.push_back({ rva, code_size, name_index });
        return;
    }

    FunctionEntry& existing = functions_[it->second];
    if (existing.code_size == 0 && code_size != 0) {
        existing.code_size = code_size;
        existing.name_index = name_index;
    }
}
