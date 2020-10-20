
#include <filesystem>
#include <fstream>
#include <iostream>

#include <llvm/ADT/ArrayRef.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/ErrorOr.h>
#include <llvm/Support/Parallel.h>
#include <llvm/Support/MemoryBuffer.h>
#include "llvm/DebugInfo/CodeView/ContinuationRecordBuilder.h"
#include "llvm/DebugInfo/CodeView/SimpleTypeSerializer.h"
#include <llvm/DebugInfo/CodeView/AppendingTypeTableBuilder.h>
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include "llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h"
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>

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

enum SymbolType { S_PUB32, S_GPROC32, S_PROCREF };
NLOHMANN_JSON_SERIALIZE_ENUM(SymbolType, {
                                             {S_PUB32, "S_PUB32"},
                                             {S_GPROC32, "S_GPROC32"},
                                             {S_PROCREF, "S_PROCREF"},
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
        // TagRecord(TypeRecordKind::Union, MemberCount, Options, FieldList, Name, UniqueName), Size(Size)
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

        uint64_t address = json["address"].get<uint64_t>();
        map_address_to_offset(json["address"], symbol.Offset, symbol.Segment);
        bool function = json["function"].get<bool>();
        if (function) {
            symbol.setFlags(llvm::codeview::PublicSymFlags::Function);
        } else {
            symbol.setFlags(llvm::codeview::PublicSymFlags::None);
        }
    }
};

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
    dbi.setFlags(llvm::pdb::DbiFlags::FlagIncrementalMask);
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
            std::cerr << "unknown type: " << type << std::endl;
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

    // add public symbols
    std::vector<llvm::pdb::BulkPublic> symbols;
    auto &gsi = builder.getGsiBuilder();
    for (auto entry : json["symbols"]) {
        SymbolType type;
        entry.at("type").get_to(type);
        switch (type) {
        case SymbolType::S_PUB32:
            symbols.push_back(std::move(entry.get<llvm::pdb::BulkPublic>()));
            break;
        default:
            std::cerr << "unknown type: " << type << std::endl;
            break;
        }
    }

    std::cout << "public symbols: " << symbols.size() << std::endl;
    if (symbols.size() > 0) {
        gsi.addPublicSymbols(std::move(symbols));
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