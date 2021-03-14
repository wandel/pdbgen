
#include <filesystem>
#include <fstream>
#include <iostream>

#include "llvm/DebugInfo/CodeView/ContinuationRecordBuilder.h"
#include "llvm/DebugInfo/CodeView/SimpleTypeSerializer.h"
#include "llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h"
#include <llvm/ADT/ArrayRef.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/DebugInfo/CodeView/AppendingTypeTableBuilder.h>
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/CodeView/SymbolRecordHelpers.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Parallel.h>

#include "lyra.hpp"
#include "nlohmann.hpp"

llvm::ExitOnError ExitOnError;

llvm::BumpPtrAllocator allocator;
llvm::codeview::AppendingTypeTableBuilder ttb_tpi(allocator);
llvm::codeview::AppendingTypeTableBuilder ttb_ipi(allocator);
llvm::object::COFFObjectFile *coff = nullptr;

std::map<std::string, llvm::codeview::TypeIndex> type_cache;

llvm::codeview::TypeIndex lookup(std::string key) {
    // for any key < 0x1000 we will treat it as a builtin codeview type
    if (key._Starts_with("0x")) {
        try {
            uint32_t tmp = std::stoul(key, nullptr, 16);
            if (tmp < 0x1000) {
                return llvm::codeview::TypeIndex::TypeIndex(tmp);
            }
        } catch (std::exception) {
            // key was not a valid hex number, so we will treat it like a custom type
        }
    }

    auto entry = type_cache.find(key);
    if (entry == type_cache.end()) {
        std::string const id = key.data();
        throw std::runtime_error("out-of-order type: id=" + id);
    }

    return entry->second;
}

template <typename T> llvm::codeview::TypeIndex insert(std::string key, T &record) {
    llvm::codeview::TypeIndex idx = ttb_tpi.writeLeafType(record);
    type_cache[key] = idx;
    return idx;
}

void map_address_to_offset(nlohmann::json json, uint32_t &offset, uint16_t &segment) {
    // we cant calculate the segment and offset in the decoder because we
    // dont have access to the coff object...
    // TODO refactor this!
    uint64_t address = json.get<uint64_t>();
    for (auto &section : coff->sections()) {
        uint64_t start = section.getAddress();
        uint64_t end = start + section.getSize();
        if (address >= start && address < end) {
            offset = address - start;
            segment = section.getIndex() + 1;
            return;
        }
    }
    std::string msg = "failed to map address to segment/offset: ";
    throw std::runtime_error(msg + json.dump());
}

enum RecordType {
    LF_ARRAY,
    LF_POINTER,
    LF_PROCEDURE,
    LF_ENUM,
    LF_MFUNCTION,
    LF_STRUCTURE,
    LF_MEMBER,
    LF_ONEMETHOD,
    LF_METHOD,
    LF_BITFIELD,
    LF_UNION,
    LF_FUNC_ID,
};

NLOHMANN_JSON_SERIALIZE_ENUM(RecordType, {
                                             {LF_ARRAY, "LF_ARRAY"},
                                             {LF_POINTER, "LF_POINTER"},
                                             {LF_ENUM, "LF_ENUM"},
                                             {LF_PROCEDURE, "LF_PROCEDURE"},
                                             {LF_MFUNCTION, "LF_MFUNCTION"},
                                             {LF_STRUCTURE, "LF_STRUCTURE"},
                                             {LF_MEMBER, "LF_MEMBER"},
                                             {LF_ONEMETHOD, "LF_ONEMETHOD"},
                                             {LF_METHOD, "LF_METHOD"},
                                             {LF_BITFIELD, "LF_BITFIELD"},
                                             {LF_UNION, "LF_UNION"},
                                             {LF_FUNC_ID, "LF_FUNC_ID"},
                                         });

enum SymbolType { S_PUB32, S_GPROC32, S_PROCREF, S_BPREL32, S_REGREL32, S_FRAMEPROC, S_END };
NLOHMANN_JSON_SERIALIZE_ENUM(SymbolType, {
                                             {S_PUB32, "S_PUB32"},
                                             {S_GPROC32, "S_GPROC32"},
                                             {S_PROCREF, "S_PROCREF"},
                                             {S_BPREL32, "S_BPREL32"},
                                             {S_REGREL32, "S_REGREL32"},
                                             {S_FRAMEPROC, "S_FRAMEPROC"},
                                             {S_END, "S_END"},
                                         });

int sortByName(const llvm::pdb::BulkPublic &L, const llvm::pdb::BulkPublic &R) { return strcmp(L.Name, R.Name); }

// We define some custom serializes for llvm::codeview items to clean up the main logic.
template <> struct nlohmann::adl_serializer<llvm::StringRef> {
    static void to_json(nlohmann::json &json, const llvm::StringRef &str) {}
    static void from_json(const nlohmann::json &json, llvm::StringRef &str) {
        // llvm::StringRef uses the std::string buffer, which will be cleaned up after the call
        // so we will .copy() to copy the string into the allocator so we can use it later.
        str = llvm::StringRef(json.get<std::string>()).copy(allocator);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::ClassOptions> {
    static void to_json(nlohmann::json &json, const llvm::codeview::ClassOptions &options) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::ClassOptions &options) {
        options = llvm::codeview::ClassOptions::None;
        for (std::string element : json) {
            if (element == "forwardref") {
                options |= llvm::codeview::ClassOptions::ForwardReference;
            }
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::TypeIndex> {
    static void to_json(nlohmann::json &json, const llvm::codeview::TypeIndex &index) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::TypeIndex &index) {
        std::string key = json.get<std::string>();
        index = lookup(key);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::BitFieldRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::BitFieldRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::BitFieldRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::BitField;
        json.at("type_id").get_to(record.Type);
        json.at("bit_offset").get_to(record.BitOffset);
        json.at("bit_size").get_to(record.BitSize);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::ArrayRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::ArrayRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::ArrayRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Array;
        json.at("size").get_to(record.Size);
        json.at("index_type").get_to(record.IndexType);
        json.at("element_type").get_to(record.ElementType);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::PointerRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::PointerRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::PointerRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Pointer;
        if (coff->is64()) {
            record.setAttrs(llvm::codeview::PointerKind::Near64, llvm::codeview::PointerMode::Pointer,
                            llvm::codeview::PointerOptions::None, 8);
        } else {
            record.setAttrs(llvm::codeview::PointerKind::Near32, llvm::codeview::PointerMode::Pointer,
                            llvm::codeview::PointerOptions::None, 4);
        }
        json.at("referent_type").get_to(record.ReferentType);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::EnumeratorRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::EnumeratorRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::EnumeratorRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Enumerator;
        json.at("name").get_to(record.Name);
        // ghidra uses java's "long" type for all values, so we will use int64_t here
        int64_t value = json.at("value").get<int64_t>();
        // it seems like APSInt "signed" is based on value (value < 0) not type (int vs uint)
        record.Value = llvm::APSInt(64, value >= 0);
        record.Value = value;
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::EnumRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::EnumRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::EnumRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Enum;
        json.at("name").get_to(record.Name);
        json.at("underlying_type").get_to(record.UnderlyingType);
        json.at("options").get_to(record.Options);
        if (json.contains("unique_name")) {
            json.at("unique_name").get_to(record.UniqueName);
            record.Options |= llvm::codeview::ClassOptions::HasUniqueName;
        }

        // build list of enum values
        record.MemberCount = 0;
        record.FieldList = llvm::codeview::TypeIndex::None();

        llvm::codeview::ContinuationRecordBuilder cb;
        cb.begin(llvm::codeview::ContinuationRecordKind::FieldList);
        for (auto field : json["fields"]) {
            cb.writeMemberType(field.get<llvm::codeview::EnumeratorRecord>());
            record.MemberCount++;
        }

        if (record.MemberCount > 0) {
            record.FieldList = ttb_tpi.insertRecord(cb);
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::DataMemberRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::DataMemberRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::DataMemberRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::DataMember;
        json.at("type_id").get_to(record.Type);
        json.at("offset").get_to(record.FieldOffset);
        json.at("name").get_to(record.Name);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::OneMethodRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::OneMethodRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::OneMethodRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::OneMethod;
        record.Attrs = llvm::codeview::MemberAttributes();
        record.VFTableOffset = -1;
        json.at("type_id").get_to(record.Type);
        json.at("name").get_to(record.Name);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::OverloadedMethodRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::OverloadedMethodRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::OverloadedMethodRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::OverloadedMethod;
        record.NumOverloads = 0;
        record.MethodList = llvm::codeview::TypeIndex::None();
        json.at("name").get_to(record.Name);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::ClassRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::ClassRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::ClassRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Struct;
        record.Options = llvm::codeview::ClassOptions::None;
        record.DerivationList = llvm::codeview::TypeIndex::None();
        record.VTableShape = llvm::codeview::TypeIndex::None();

        json.at("name").get_to(record.Name);
        json.at("options").get_to(record.Options);
        json.at("size").get_to(record.Size);
        if (json.contains("unique_name")) {
            json.at("unique_name").get_to(record.UniqueName);
            record.Options |= llvm::codeview::ClassOptions::HasUniqueName;
        }

        // build list of fields
        record.MemberCount = 0;
        record.FieldList = llvm::codeview::TypeIndex::None();

        llvm::codeview::ContinuationRecordBuilder cb;
        cb.begin(llvm::codeview::ContinuationRecordKind::FieldList);
        for (auto field : json["fields"]) {
            RecordType type;
            field.at("type").get_to(type);
            switch (type) {
            case LF_MEMBER:
                cb.writeMemberType(field.get<llvm::codeview::DataMemberRecord>());
                break;
            case LF_ONEMETHOD:
                cb.writeMemberType(field.get<llvm::codeview::OneMethodRecord>());
                break;
            case LF_METHOD:
                cb.writeMemberType(field.get<llvm::codeview::OverloadedMethodRecord>());
                break;
            default:
                std::cout << "unknown member type:" << field << std::endl;
                assert(false);
            }
            record.MemberCount++;
        }

        if (record.MemberCount > 0) {
            record.FieldList = ttb_tpi.insertRecord(cb);
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::UnionRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::UnionRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::UnionRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Union;
        record.MemberCount = 0;
        json.at("size").get_to(record.Size);
        json.at("name").get_to(record.Name);
        json.at("options").get_to(record.Options);
        if (json.contains("unique_name")) {
            json.at("unique_name").get_to(record.UniqueName);
            record.Options |= llvm::codeview::ClassOptions::HasUniqueName;
        }

        llvm::codeview::ContinuationRecordBuilder cb;
        cb.begin(llvm::codeview::ContinuationRecordKind::FieldList);
        for (auto field : json["fields"]) {
            RecordType type = field["type"].get<RecordType>();
            switch (type) {
            case LF_MEMBER:
                cb.writeMemberType(field.get<llvm::codeview::DataMemberRecord>());
                break;
            case LF_ONEMETHOD:
                cb.writeMemberType(field.get<llvm::codeview::OneMethodRecord>());
                break;
            case LF_METHOD:
                cb.writeMemberType(field.get<llvm::codeview::OverloadedMethodRecord>());
                break;
            default:
                std::cout << "unknown member type:" << field << std::endl;
                assert(false);
            }
            record.MemberCount++;
        }

        if (record.MemberCount > 0) {
            record.FieldList = ttb_tpi.insertRecord(cb);
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::FunctionOptions> {
    static void to_json(nlohmann::json &json, const llvm::codeview::FunctionOptions &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::FunctionOptions &record) {
        record = llvm::codeview::FunctionOptions::None;
        for (std::string option : json) {
            if (option == "constructor") {
                record |= llvm::codeview::FunctionOptions::Constructor;
            }
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::CallingConvention> {
    static void to_json(nlohmann::json &json, const llvm::codeview::CallingConvention &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::CallingConvention &record) {
        record = llvm::codeview::CallingConvention::FarC;
        // TODO: this needs be fixed somehow.
        // Ghidra will use "" or "unknown" if it cant determine to calling convention
        // msvc seems to be generating "cdecl" in the pdbs for x64
        for (std::string option : json) {
            if (option == "__cdecl") {
                record = llvm::codeview::CallingConvention::NearC;
            } else if (option == "__stdcall") {
                record = llvm::codeview::CallingConvention::NearStdCall;
            } else if (option == "__fastcall") {
                record = llvm::codeview::CallingConvention::NearFast;
            } else if (option == "__thiscall") {
                record = llvm::codeview::CallingConvention::ThisCall;
            } else if (option == "syscall") {
                record = llvm::codeview::CallingConvention::NearSysCall;
            } else if (option == "") {
                record = llvm::codeview::CallingConvention::FarC;
            } else if (option == "unknown") {
                record = llvm::codeview::CallingConvention::FarC;
            } else {
                std::string err = "unknown calling convention:";
                throw std::runtime_error(err + option);
            }
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::ProcedureRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::ProcedureRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::ProcedureRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::Procedure;
        json.at("return_type").get_to(record.ReturnType);
        json.at("calling_convention").get_to(record.CallConv);
        if (json.contains("options")) {
            json.at("options").get_to(record.Options);
        }

        llvm::codeview::ArgListRecord args(llvm::codeview::TypeRecordKind::ArgList);
        for (std::string arg : json.at("parameters")) {
            llvm::codeview::TypeIndex idx = lookup(arg);
            args.ArgIndices.push_back(idx);
        }

        record.ParameterCount = args.ArgIndices.size();
        record.ArgumentList = ttb_tpi.writeLeafType(args);
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::FuncIdRecord> {
    static void to_json(nlohmann::json &json, const llvm::codeview::FuncIdRecord &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::FuncIdRecord &record) {
        record.Kind = llvm::codeview::TypeRecordKind::FuncId;
        json.at("name").get_to(record.Name);
        json.at("function_type").get_to(record.FunctionType);
        json.at("parent_scope").get_to(record.ParentScope);
    }
};

template <> struct nlohmann::adl_serializer<llvm::pdb::BulkPublic> {
    static void to_json(nlohmann::json &json, const llvm::pdb::BulkPublic &symbol) {}
    static void from_json(const nlohmann::json &json, llvm::pdb::BulkPublic &symbol) {
        std::string name = json["name"].get<std::string>();
        // to to make a copy of this, as the std::string will be deallocated after the call.
        symbol.Name = allocator.Allocate<char>(name.size());
        memcpy((void *)symbol.Name, name.c_str(), name.size());
        symbol.NameLen = name.size();

        map_address_to_offset(json["address"], symbol.Offset, symbol.Segment);
        bool function = json["function"].get<bool>();
        if (function) {
            symbol.setFlags(llvm::codeview::PublicSymFlags::Function);
        } else {
            symbol.setFlags(llvm::codeview::PublicSymFlags::None);
        }
    }
};

template <typename T> llvm::codeview::CVSymbol WriteOneSymbol(T sym) {
    return llvm::codeview::SymbolSerializer::writeOneSymbol(sym, allocator, llvm::codeview::CodeViewContainer::Pdb);
}

template <> struct nlohmann::adl_serializer<llvm::codeview::ProcSymFlags> {
    static void to_json(nlohmann::json &json, const llvm::codeview::ProcSymFlags &record) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::ProcSymFlags &record) {
        record = llvm::codeview::ProcSymFlags::None;
        for (std::string option : json) {
            if (option == "framepointer") {
                record |= llvm::codeview::ProcSymFlags::HasFP;
            }
        }
    }
};

template <> struct nlohmann::adl_serializer<llvm::codeview::RegisterId> {
    static void to_json(nlohmann::json &json, const llvm::codeview::RegisterId &id) {}
    static void from_json(const nlohmann::json &json, llvm::codeview::RegisterId &id) {
        std::string reg = json.get<std::string>();

        if (reg.compare("RSP") == 0) {
            id = llvm::codeview::RegisterId::RSP;
        } else {
            std::string msg = "invalid register: '" + reg + "'";
            llvm::llvm_unreachable_internal(msg.c_str(), __FILE__, __LINE__);
        }
    }
};

// There is no default constructor for these types, so we will have to do it manually.
llvm::codeview::CVSymbol from_json_gproc(const nlohmann::json &json) {
    llvm::codeview::ProcSym record(llvm::codeview::SymbolRecordKind::GlobalProcSym);
    // record.Flags = llvm::codeview::ProcSymFlags::None;

    json.at("name").get_to(record.Name);
    map_address_to_offset(json["address"], record.CodeOffset, record.Segment);
    json.at("code_size").get_to(record.CodeSize);

    // This is the offset (into the module stream) of the S_END for this symbol.
    // Im currently unsure how to determine this at this point, might need a refactor.
    json.at("end").get_to(record.End);

    json.at("function_type").get_to(record.FunctionType);
    json.at("debug_start").get_to(record.DbgStart);
    json.at("debug_end").get_to(record.DbgEnd);
    // json.at("parent").get_to(record.Parent);
    json.at("flags").get_to(record.Flags);
    return WriteOneSymbol(record);
}

llvm::codeview::CVSymbol from_json_frameproc(const nlohmann::json &json) {
    llvm::codeview::FrameProcSym record(llvm::codeview::SymbolRecordKind::FrameProcSym);
    record.Flags = llvm::codeview::FrameProcedureOptions::None;

    json.at("size").get_to(record.TotalFrameBytes);
    json.at("padding_size").get_to(record.PaddingFrameBytes);
    json.at("offset_to_padding").get_to(record.OffsetToPadding);
    json.at("bytes_of_callee_saved_registers").get_to(record.BytesOfCalleeSavedRegisters);

    // hardcoded these for the moment. we would need to deduce these from Ghidra
    record.Flags |=
        llvm::codeview::FrameProcedureOptions(uint32_t(llvm::codeview::EncodedFramePtrReg::StackPtr) << 14U);
    record.Flags |=
        llvm::codeview::FrameProcedureOptions(uint32_t(llvm::codeview::EncodedFramePtrReg::StackPtr) << 16U);
    record.Flags |=
        llvm::codeview::FrameProcedureOptions::OptimizedForSpeed; // not sure if this is needed, just a test exe/pdb.
    // json.at("exception_handler_offset").get_to(record.OffsetOfExceptionHandler);
    // json.at("???").get_to(record.SectionIdOfExceptionHandler);
    return WriteOneSymbol(record);
}

llvm::codeview::CVSymbol from_json_bprel(const nlohmann::json &json) {
    llvm::codeview::BPRelativeSym record(llvm::codeview::SymbolRecordKind::BPRelativeSym);
    json.at("type_id").get_to(record.Type);
    json.at("name").get_to(record.Name);
    json.at("offset").get_to(record.Offset);
    return WriteOneSymbol(record);
}

llvm::codeview::CVSymbol from_json_regrel(const nlohmann::json &json) {
    llvm::codeview::RegRelativeSym record(llvm::codeview::SymbolRecordKind::RegRelativeSym);
    json.at("type_id").get_to(record.Type);
    json.at("name").get_to(record.Name);
    json.at("offset").get_to(record.Offset);
    json.at("register").get_to(record.Register);
    return WriteOneSymbol(record);
}

// Copied wholesale from lld
struct ScopeRecord {
    llvm::support::ulittle32_t ptrParent;
    llvm::support::ulittle32_t ptrEnd;
};

struct SymbolScope {
    ScopeRecord *openingRecord;
    uint32_t scopeOffset;
};

static void scopeStackOpen(llvm::SmallVectorImpl<SymbolScope> &stack, uint32_t curOffset,
                           llvm::codeview::CVSymbol &sym) {
    assert(llvm::codeview::symbolOpensScope(sym.kind()));
    SymbolScope s;
    s.scopeOffset = curOffset;
    s.openingRecord = const_cast<ScopeRecord *>(reinterpret_cast<const ScopeRecord *>(sym.content().data()));
    s.openingRecord->ptrParent = stack.empty() ? 0 : stack.back().scopeOffset;
    stack.push_back(s);
}

static void scopeStackClose(llvm::SmallVectorImpl<SymbolScope> &stack, uint32_t curOffset) {
    assert(!stack.empty());
    SymbolScope s = stack.pop_back_val();
    s.openingRecord->ptrEnd = curOffset;
}

// main logic here
int process(std::filesystem::path exe_path, std::filesystem::path json_path, std::filesystem::path pdb_path) {
    std::ifstream json_file(json_path);
    assert(json_file.is_open());

    nlohmann::json json;
    json_file >> json;

    llvm::pdb::PDBFileBuilder builder(allocator);

    // initialize builder
    ExitOnError(builder.initialize(4096));

    // Create streams in MSF for predefined streams, namely PDB, TPI, DBI and IPI.
    for (int i = 0; i < llvm::pdb::kSpecialStreamCount; i++) {
        ExitOnError(builder.getMsfBuilder().addStream(0));
    }

    // we could eliminate the need for this because ghidra has all the required information
    // however I want to port this to IDA, which discards some of this information after analysis.
    auto expected = llvm::object::createBinary(exe_path.string());
    if (!expected) {
        ExitOnError(expected.takeError());
    }
    auto binary = expected->getBinary();

    std::cout << "filename=" << exe_path << " type=0x" << std::hex << binary->getType() << std::endl;
    assert(binary->isCOFF());

    coff = llvm::dyn_cast<llvm::object::COFFObjectFile>(binary);
    llvm::pdb::InfoStreamBuilder &info = builder.getInfoBuilder();
    llvm::pdb::DbiStreamBuilder &dbi = builder.getDbiBuilder();

    // mimicking VS2019 for these values.
    // you can get these details using llvm's pdbutil.
    // llvm/build/debug/bin/llvm-pdbutil.exe pdb2yaml --all <path-to-pdb> > dump.yml
    info.setVersion(llvm::pdb::PdbImplVC70);
    info.addFeature(llvm::pdb::PdbRaw_FeatureSig::VC140);
    info.setHashPDBContentsToGUID(false);

    dbi.setBuildNumber(36379);
    // dbi.setFlags(llvm::pdb::DbiFlags::FlagStrippedMask);
    dbi.setPdbDllRbld(0);
    dbi.setPdbDllVersion(29111);
    dbi.setVersionHeader(llvm::pdb::PdbDbiV70);
    for (llvm::object::debug_directory const &dir : coff->debug_directories()) {
        info.setSignature(dir.TimeDateStamp);
        if (dir.Type != llvm::COFF::IMAGE_DEBUG_TYPE_CODEVIEW) {
            continue;
        }

        llvm::StringRef filename;
        const llvm::codeview::DebugInfo *debug;
        ExitOnError(coff->getDebugPDBInfo(debug, filename));

        if (debug->Signature.CVSignature != llvm::OMF::Signature::PDB70) {
            continue;
        }

        llvm::codeview::GUID guid;
        info.setAge(debug->PDB70.Age);
        dbi.setAge(debug->PDB70.Age);
        std::memcpy(&guid, debug->PDB70.Signature, sizeof(guid));
        info.setGuid(guid);
    }

    if (coff->is64()) {
        dbi.setMachineType(llvm::pdb::PDB_Machine::Amd64);
    } else {
        dbi.setMachineType(llvm::pdb::PDB_Machine::x86);
    }

    /////////////////////////////////////////////////////////////////////
    //                              Add Types                          //
    /////////////////////////////////////////////////////////////////////

    auto &ipi = builder.getIpiBuilder();
    ipi.setVersionHeader(llvm::pdb::PdbTpiV80);

    auto &tpi = builder.getTpiBuilder();
    tpi.setVersionHeader(llvm::pdb::PdbTpiV80);

    for (auto entry : json["types"]) {
        // std::cout << entry << std::endl;
        RecordType type = entry.at("type");
        std::string id = entry["id"].get<std::string>();
        switch (type) {
        case LF_ARRAY:
            insert(id, entry.get<llvm::codeview::ArrayRecord>());
            break;
        case LF_ENUM:
            insert(id, entry.get<llvm::codeview::EnumRecord>());
            break;
        case LF_POINTER:
            insert(id, entry.get<llvm::codeview::PointerRecord>());
            break;
        case LF_STRUCTURE:
            insert(id, entry.get<llvm::codeview::ClassRecord>());
            break;
        case LF_PROCEDURE:
            insert(id, entry.get<llvm::codeview::ProcedureRecord>());
            break;
        case LF_UNION:
            insert(id, entry.get<llvm::codeview::UnionRecord>());
            break;
        case LF_BITFIELD:
            insert(id, entry.get<llvm::codeview::BitFieldRecord>());
            break;
        case LF_FUNC_ID:
            ttb_ipi.writeLeafType(entry.get<llvm::codeview::FuncIdRecord>());
            break;
        default:
            std::cerr << "unknown data type: " << type << std::endl;
            break;
        }
    }
    ttb_tpi.ForEachRecord([&tpi](llvm::codeview::TypeIndex ti, const llvm::codeview::CVType &type) {
        uint32_t hash = ExitOnError(llvm::pdb::hashTypeRecord(type));
        tpi.addTypeRecord(type.RecordData, hash);
    });
    std::cout << "tpi: " << tpi.getRecordCount() << std::endl;

    ttb_ipi.ForEachRecord([&ipi](llvm::codeview::TypeIndex ti, const llvm::codeview::CVType &type) {
        uint32_t hash = ExitOnError(llvm::pdb::hashTypeRecord(type));
        ipi.addTypeRecord(type.RecordData, hash);
    });
    std::cout << "ipi: " << ipi.getRecordCount() << std::endl;

    // lib\DebugInfo\PDB\Native\DbiStreamBuilder.cpp
    llvm::StringRef modName = "fake.obj";
    llvm::pdb::DbiModuleDescriptorBuilder &moduleDBI = ExitOnError(dbi.addModuleInfo(modName));
    moduleDBI.setObjFileName(modName);

    // SC[.text] |mod = 0, 0001 : 1136, size = 374, data crc = 2800844987, reloc crc = 0
    llvm::pdb::SectionContrib SC = {};
    SC.Size = 374;
    SC.ISect = 1;
    SC.Off = 1136;
    SC.DataCrc = 2800844987;
    // IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
    SC.Characteristics = 0x00000020 | 0x00500000 | 0x20000000 | 0x40000000;

    moduleDBI.setFirstSectionContrib(SC);

    llvm::codeview::ObjNameSym objname(llvm::codeview::SymbolKind::S_OBJNAME);
    objname.Name = modName;
    moduleDBI.addSymbol(WriteOneSymbol(objname));

    // 64 | S_COMPILE3[size = 60]
    // machine = intel x86 - x64,
    // Ver = Microsoft(R) Optimizing Compiler,
    // language = c++ frontend = 19.27.29112.0,
    // backend = 19.27.29112.0
    // flags = security checks | hot patchable
    llvm::codeview::Compile3Sym compile(llvm::codeview::SymbolKind::S_COMPILE3);

    // just copying VS2019 for alot of these values
    if (coff->is64()) {
        compile.Machine = llvm::codeview::CPUType::X64;
    } else {
        compile.Machine = llvm::codeview::CPUType::Pentium3;
    }
    compile.Version = "Microsoft (R) Optimizing Compiler";
    compile.setLanguage(llvm::codeview::SourceLanguage::Cpp);

    // frontend = 19.27.29112.0, backend = 19.27.29112.0
    compile.VersionFrontendMajor = 19;
    compile.VersionFrontendMinor = 27;
    compile.VersionFrontendBuild = 29112;
    compile.VersionFrontendQFE = 0;

    compile.VersionBackendMajor = 19;
    compile.VersionBackendMinor = 27;
    compile.VersionBackendBuild = 29112;
    compile.VersionBackendQFE = 0;

    moduleDBI.addSymbol(WriteOneSymbol(compile));

    // alot of this code is from lld\COFF\PDB.cpp
    llvm::codeview::CVSymbol newSym;
    std::vector<llvm::pdb::BulkPublic> publics;
    llvm::SmallVector<SymbolScope, 4> scopes;

    auto &gsi = builder.getGsiBuilder();
    for (auto entry : json["symbols"]) {
        uint64_t offset = moduleDBI.getNextSymbolOffset();

        SymbolType type;
        entry.at("type").get_to(type);

        llvm::codeview::ProcRefSym pr(llvm::codeview::SymbolKind::S_PROCREF);

        switch (type) {
        case SymbolType::S_PUB32:
            publics.push_back(std::move(entry.get<llvm::pdb::BulkPublic>()));
            break;
        case SymbolType::S_GPROC32:
            newSym = from_json_gproc(entry);
            scopeStackOpen(scopes, moduleDBI.getNextSymbolOffset(), newSym);
            moduleDBI.addSymbol(newSym);
            pr.Module = moduleDBI.getModuleIndex() + 1;
            pr.SymOffset = offset;
            entry.at("name").get_to(pr.Name);
            gsi.addGlobalSymbol(pr);
            break;
        case SymbolType::S_FRAMEPROC:
            std::cout << entry << std::endl;
            moduleDBI.addSymbol(from_json_frameproc(entry));
            break;
        case SymbolType::S_BPREL32:
            moduleDBI.addSymbol(from_json_bprel(entry));
            break;
        case SymbolType::S_REGREL32:
            moduleDBI.addSymbol(from_json_regrel(entry));
            break;
        case SymbolType::S_END:
            newSym = WriteOneSymbol(llvm::codeview::ScopeEndSym(llvm::codeview::SymbolRecordKind::ScopeEndSym));
            scopeStackClose(scopes, moduleDBI.getNextSymbolOffset());
            moduleDBI.addSymbol(newSym);
            break;
        default:
            std::cerr << "unknown symbol type: " << entry << std::endl;
            break;
        }
    }

    // Mod 0044 | `*Linker *`: 4 | S_OBJNAME[size = 20] sig = 0, `* Linker *` 24 | S_COMPILE3[size = 48] machine = intel
    // x86 - x64, Ver = Microsoft(R) LINK, language = link frontend = 0.0.0.0, backend = 14.27.29112.0 flags = none

    // llvm::pdb::DbiModuleDescriptorBuilder &linkerDBI = ExitOnError(dbi.addModuleInfo("* Linker *"));
    // linkerDBI.setObjFileName("* Linker *");

    // llvm::codeview::ObjNameSym linkname(llvm::codeview::SymbolKind::S_OBJNAME);
    // linkname.Name = "* Linker *";
    // linkerDBI.addSymbol(WriteOneSymbol(linkname));

    // llvm::codeview::Compile3Sym linker(llvm::codeview::SymbolKind::S_COMPILE3);

    // // just copying VS2019 for alot of these values
    // if (coff->is64()) {
    //     linker.Machine = llvm::codeview::CPUType::X64;
    // } else {
    //     linker.Machine = llvm::codeview::CPUType::Pentium3;
    // }
    // linker.Version = "Microsoft(R) LINK";
    // linker.setLanguage(llvm::codeview::SourceLanguage::Link);

    // // frontend = 19.27.29112.0, backend = 19.27.29112.0
    // linker.VersionFrontendMajor = 0;
    // linker.VersionFrontendMinor = 0;
    // linker.VersionFrontendBuild = 0;
    // linker.VersionFrontendQFE = 0;

    // linker.VersionBackendMajor = 14;
    // linker.VersionBackendMinor = 10;
    // linker.VersionBackendBuild = 25019;
    // linker.VersionBackendQFE = 0;

    // linkerDBI.addSymbol(WriteOneSymbol(linker));

    // llvm::codeview::EnvBlockSym ebs(llvm::codeview::SymbolRecordKind::EnvBlockSym);
    // ebs.Fields.push_back("cwd");
    // ebs.Fields.push_back("C:\\Workspace\\example\\build64");
    // ebs.Fields.push_back("exe");
    // ebs.Fields.push_back("C:\\Program Files(x86)\\Microsoft Visual
    // Studio\\2019\\Enterprise\\VC\\Tools\\MSVC\\14.27.29110\\bin\\HostX64\\x64\\link.exe");
    // ebs.Fields.push_back("pdb");
    // ebs.Fields.push_back("C:\\Workspace\\example\\build64\\Debug\\app.pdb");
    // ebs.Fields.push_back("cmd");
    // ebs.Fields.push_back("/ERRORREPORT:QUEUE /OUT:C:\\Workspace\\example\\build64\\Debug\\app.exe /INCREMENTAL
    // /NOLOGO /MANIFEST \"/MANIFESTUAC:level='asInvoker' uiAccess='false'\" /manifest:embed /DEBUG
    // /PDB:C:/Workspace/example/build64/Debug/app.pdb /SUBSYSTEM:CONSOLE /TLBID:1 /DYNAMICBASE /NXCOMPAT
    // /IMPLIB:C:/Workspace/example/build64/Debug/app.lib /MACHINE : X64 /machine : x64");

    // linkerDBI.addSymbol(WriteOneSymbol(ebs));

    std::cout << "publics: " << publics.size() << std::endl;
    if (publics.size() > 0) {
        gsi.addPublicSymbols(std::move(publics));
    }

    // Add Section Map stream.
    // We need to do this because otherwise windbg wont pick up the public symbols (not sure why).
    auto count = coff->getNumberOfSections();
    const llvm::object::coff_section *section = nullptr;
    for (const llvm::object::SectionRef &Sec : coff->sections()) {
        section = coff->getCOFFSection(Sec);
        break;
    }

    llvm::ArrayRef<llvm::object::coff_section> sections(section, count);
    dbi.createSectionMap(sections);
    auto sectionsTable = llvm::ArrayRef<uint8_t>(reinterpret_cast<const uint8_t *>(sections.begin()),
                                                 reinterpret_cast<const uint8_t *>(sections.end()));
    ExitOnError(dbi.addDbgStream(llvm::pdb::DbgHeaderType::SectionHdr, sectionsTable));

    // finally save everything out
    builder.commit(pdb_path.string(), &builder.getInfoBuilder().getGuid());

    return 0;
}

int main(int argc, char **argv) {
    bool show_help = false;
    std::filesystem::path exe;
    std::filesystem::path pdb;
    std::filesystem::path json;

    auto cli = lyra::cli();
    cli |= lyra::help(show_help);
    cli |= lyra::arg(exe, "executable").required().help("The path to the original executable");
    cli |= lyra::opt(json, "path")["-j"]["--json"].help("The json file emitted from ghidra");
    cli |= lyra::opt(pdb, "path")["-o"]["--pdb"].help("The path to save the new .pdb");

    auto result = cli.parse({argc, argv});
    if (!result) {
        std::cerr << "Error in command line: " << result.errorMessage() << std::endl;
        std::cout << cli << std::endl;
        return 1;
    }

    if (show_help) {
        std::cout << cli << std::endl;
        return 0;
    }

    exe = std::filesystem::absolute(exe);
    if (json.empty()) {
        json = std::filesystem::path(exe).concat(".json");
    }

    if (pdb.empty()) {
        pdb = std::filesystem::path(exe);
        pdb.replace_extension(".pdb");
    }

    std::cout << "exe: " << exe << std::endl;
    std::cout << "json: " << json << std::endl;
    std::cout << "pdb: " << pdb << std::endl;

    if (!std::filesystem::exists(exe)) {
        std::cerr << exe << " does not exist" << std::endl;
        return 2;
    }
    if (!std::filesystem::exists(json)) {
        std::cerr << json << " does not exist" << std::endl;
        return 2;
    }

    try {
        return process(exe, json, pdb);
    } catch (nlohmann::json::exception e) {
        std::cout << "failed to parse json" << e.what() << std::endl;
        return -1;
    } catch (std::exception e) {
        std::cout << "unknown error:" << e.what() << std::endl;
        return -2;
    }
}