//Generates a PDB containing public symbols and type information derived from ghidra's database
//@author Brett Wandel
//@category Windows
//@keybinding ctrl G
//@menupath Tools.Generate PDB
//@toolbar 

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.commons.io.FilenameUtils;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import generic.util.Path;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.UniversalID;

public class PdbGen extends GhidraScript {
	// Note: we are manually serializing json here, this is just to avoid any dependencies.
	// this means it will break if we have any fields that need escaping.
	Map<String, String> typedefs = new HashMap<String, String>();
	List<String> serialized = new ArrayList<String>();
	Map<String, String> forwardDeclared = new HashMap<String, String>();
	
	Map<Address, FunctionDefinition> entrypoints = new HashMap<Address, FunctionDefinition>();
	
	private boolean isSerialized(DataType dt) {
		String id = GetId(dt);
		return isSerialized(id);
	}
	
	private boolean isSerialized(String id) {
		return serialized.contains(id);
	}
	
	private void setSerialized(DataType dt) {
		String id = GetId(dt);
		serialized.add(id);
	}
	
	private String GetIdUnmapped(DataType dt) {
		if (dt == null) {
			// Not sure if this should be LF_NULLLEAF (0x0009)
			// using no type (0x0000) first, this might need to change
			return "0x0000"; // uncharacterized type (no type)
		}

		// FML... this needs to be fixed at some point.
		// this should be done as a typedef, but we can't get "/undefined" by path for some reason.
		String name = dt.getName();
		if (name.contains("-")) {
			name = name.split("-")[0];
		}
		
		if (name == "undefined") {
			return "void";
		}

		UniversalID uid = dt.getUniversalID();
		if (uid != null) {
			return uid.toString();
		}

		// a BitField does not have a unique name, so we create one
		// The hashCode is based on basetype.hashcode, bitOffset and bitSize...
		// so basetype.name:bitSize:bitOffset should be unique.
		if (dt instanceof BitFieldDataType) {
			name = String.format("%s:%d", name, ((BitFieldDataType) dt).getBitOffset());
		}
		
		// some types don't have UniversalIDs, so we use the name instead
		return name;
	}
	
	private String GetId(DataType dt) {
		String key = GetIdUnmapped(dt);

		// follow the typedefs to the original type.
		while (typedefs.containsKey(key)) {
			assert key != typedefs.get(key);
			key = typedefs.get(key);
		}

//		String before = GetIdUnmapped(dt);
//		String name = "????";
//		if (dt != null) {
//			name = dt.getPathName();
//		}
//		printf("%s : %s => %s\n", name, before, key);
		return key;
	}
	
	// Get the new ID for a type that has been forward declared.
	private String GetFwdId(DataType dt) {
		String id = GetId(dt);
		if (!forwardDeclared.containsKey(id)) {
			String alias = UUID.randomUUID().toString();
			forwardDeclared.put(id, alias);
		}
		return forwardDeclared.get(id);
	}
	
	private JsonObject dump(Pointer x) {
		if (!isSerialized(x.getDataType())) return null;
		
		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_POINTER");
		json.addProperty("referent_type", GetId(x.getDataType()));
		return json;
	}

	private JsonObject dump(Array x) {
		if (!isSerialized(x.getDataType())) return null;

		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_ARRAY");
		// TODO currently this is set to QWORD, is this different for x86/x64?
		json.addProperty("index_type", "0x0077");
		json.addProperty("element_type", GetId(x.getDataType()));
		json.addProperty("size", x.getLength());
		return json;
	}
	
	private JsonObject dump(Union x) {
		JsonArray members = new JsonArray();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) return null;
			JsonObject json = new JsonObject();
			json.addProperty("type", "LF_MEMBER");
			// TODO currently this is set to QWORD, is this different for x86/x64?
			json.addProperty("name", dt.getFieldName());
			json.addProperty("type_id", GetId(dt.getDataType()));
			json.addProperty("offset", dt.getOffset());
			json.add("attributes", new JsonArray());
			members.add(json);
		}
		
		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_UNION");
		json.addProperty("name", x.getName());
		json.addProperty("unique_name", GetFwdId(x));
		json.addProperty("size", x.getLength());
		json.add("fields", members);
		json.add("options", new JsonArray());
		return json;
	}

	private JsonObject dump(Enum x) {
		JsonArray fields = new JsonArray();
		for (long value : x.getValues()) {
			JsonObject json = new JsonObject();
			json.addProperty("name", x.getName(value));
			json.addProperty("value", value);
			fields.add(json);
		}
		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_ENUM");
		json.addProperty("size", x.getLength());
		json.addProperty("underlying_type", "0x0074");
		json.addProperty("name", x.getName());
		json.addProperty("unique_name", GetFwdId(x));
		json.add("fields", fields);
		json.add("options", new JsonArray());
		return json;
	}

	private JsonObject dump(Structure x) {
		JsonArray fields = new JsonArray();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) return null;
			
			JsonObject json = new JsonObject();
			json.addProperty("type", "LF_MEMBER");
			json.addProperty("name", dt.getFieldName());
			json.addProperty("type_id", GetId(dt.getDataType()));
			json.addProperty("offset", dt.getOffset());
			json.add("attributes", new JsonArray());
			if (dt.isBitFieldComponent()) {
				// TODO implement this
				// BitFieldDataType bfdt = (BitFieldDataType) dt.getDataType();
			}
			
			fields.add(json);
		}
		
		JsonObject json = new JsonObject();
		json.addProperty("id", GetFwdId(x));
		json.addProperty("type", "LF_STRUCTURE");
		json.addProperty("name", x.getName());
		json.addProperty("size", x.getLength());
		json.addProperty("unique_name", GetFwdId(x));
		json.add("options", new JsonArray());
		json.add("fields", fields);
		return json;
	}
	
	private JsonObject dump(BitFieldDataType x) {
		if (!isSerialized(x.getBaseDataType())) return null;

		JsonObject json = new JsonObject();
		json.addProperty("id", GetId(x));
		json.addProperty("type", "LF_BITFIELD");
		json.addProperty("type_id", GetId(x.getBaseDataType()));
		json.addProperty("bit_offset", x.getBitOffset());
		json.addProperty("bit_size", x.getBitSize());
		return json;
	}

	private List<JsonObject> dump(FunctionDefinition x) {
//		// There should be a good way of determining class, but I haven't found it yet
//		// So instead I'm just gonna check calling convention and lookup the type manually.
//		if (x.getGenericCallingConvention() == GenericCallingConvention.thiscall) {
//			DataType clz = x.getArguments()[0].getDataType();
//			if (clz instanceof Pointer) {
//				clz = ((Pointer) clz).getDataType();
//			}
//			printf("%s::%s()\n", clz.getName(), x.getName());
//		}
//		printf("function [%s] %s %s", x.getName(), GetId(x), x.getClass().getName());
		if (!isSerialized(x.getReturnType())) return null;
		JsonArray parameters = new JsonArray();
		for (ParameterDefinition p : x.getArguments()) {
			if (!isSerialized(p.getDataType())) return null;
			parameters.add(GetId(p.getDataType()));
		}
		List<JsonObject> entries = new ArrayList<JsonObject>();

		JsonObject json = new JsonObject();
		json.addProperty("type", "LF_PROCEDURE");
		json.addProperty("id", GetId(x));
		json.addProperty("name", x.getName());
		json.addProperty("return_type", GetId(x.getReturnType()));
		json.addProperty("calling_convention", x.getGenericCallingConvention().toString());
		json.add("options", new JsonArray());
		json.add("parameters", parameters);
		entries.add(json);
		
		json = new JsonObject();
		// We are creating a new id here just so it flows through our pipeline correctly with the rest of the types.
		json.addProperty("type", "LF_FUNC_ID");
		json.addProperty("id", UUID.randomUUID().toString());
		json.addProperty("name", x.getName());
		json.addProperty("function_type", GetId(x));
		json.addProperty("parent_scope", "0x0000"); // placeholder
		entries.add(json);

		return entries;
	}

	private List<JsonObject> toJson(DataType dt) {
		if (dt instanceof FunctionDefinition) {
			return dump((FunctionDefinition) dt);
		}
		
		List<JsonObject> entries = new ArrayList<JsonObject>();
		JsonObject json = null;
		if (dt instanceof Pointer) {
			json = dump((Pointer) dt);
		} else if (dt instanceof BitFieldDataType) {
			json = dump((BitFieldDataType) dt);
		} else if (dt instanceof Array) {
			json = dump((Array) dt);
		} else if (dt instanceof Union) {
			json = dump((Union) dt);
		} else if (dt instanceof Enum) {
			json = dump((Enum) dt);
		} else if (dt instanceof Structure) {
			line = dump((Structure) dt);
		} else if (dt instanceof DefaultDataType) {
			// this is "undefined" which is predefined by codeview, so we will skip it here.
			return entries;
			json = dump((Structure) dt);
		} else if (dt instanceof TypeDef){
			// Not required... we map typedefs to their underlying type before processing the rest of the types
			// I have not found any CodeView type for typedefs, so we map the types (AFAIK like the linker does).
			// implementing this *might* cleanup the output a little, but not sure if the juice is worth the squeeze
			return null;
		} else {
			printf("[PDBGEN] Unknown Type: id=%s, name=%s, class=%s\n", GetId(dt), dt.getName(), dt.getClass().getName());
			return entries;
		}

		if (json == null) {
			return null;
		}
		
		entries.add(json);
		return entries;
	}

	public void PrintMissing(DataType dt0, String msg, DataType dt1) {
		if (isSerialized(dt1)) return;
		printf("[PDBGEN] missing: %s %s %s\n", dt0.getName(), msg, GetId(dt1));
	}

	public void PrintMissing(Pointer dt) {
		PrintMissing(dt, "datatype", dt.getDataType());
	}


	public void PrintMissing(Array dt) {
		PrintMissing(dt, "datatype", dt.getDataType());
	}

	public void PrintMissing(Union dt) {
		for (DataTypeComponent component : dt.getComponents()) {
			PrintMissing(dt, component.getFieldName(), component.getDataType());
		}
	}

	public void PrintMissing(Enum dt) {
		//underlying type is hard coded
	}

	public void PrintMissing(Structure dt) {
		for (DataTypeComponent component : dt.getComponents()) {
			PrintMissing(dt, component.getFieldName(), component.getDataType());
		}
	}

	public void PrintMissing(BitFieldDataType dt) {
		PrintMissing(dt, "base type", dt.getBaseDataType());
	}

	public void PrintMissing(FunctionDefinition dt) {
		PrintMissing(dt, "return type", dt.getReturnType());
		for (ParameterDefinition p : dt.getArguments()) {
			PrintMissing(dt, p.getName(), p.getDataType());
		}
	}
	
	public void PrintMissing(DataType dt) {
		if (dt instanceof Pointer) {
			PrintMissing((Pointer) dt);
		} else if (dt instanceof BitFieldDataType) {
			PrintMissing((BitFieldDataType) dt);
		} else if (dt instanceof Array) {
			PrintMissing((Array) dt);
		} else if (dt instanceof Union) {
			PrintMissing((Union) dt);
		} else if (dt instanceof Enum) {
			PrintMissing((Enum) dt);
		} else if (dt instanceof Structure) {
			PrintMissing((Structure) dt);
		}else if (dt instanceof FunctionDefinition) {
			PrintMissing((FunctionDefinition) dt);
		} else {
			printf("[PDBGEN] Unknown Type:", dt);
		}
		return;
	}
	

	public JsonArray toJson(List<DataType> datatypes) {
		// Build forward declarations for everything, basically because I'm lazy.
		// We should only need to add forward declarations for data types that have cyclic dependencies.
		JsonArray json = buildForwardDeclarations(datatypes);

		// A naive ordered serialization. We continually iterate through the list,
		// serializing data types only once they have had all their dependencies serialized.
		// we stop looping over the list once we fail to serialize at least one data type.
		// Any data types that are missing dependent types will be left in the input list.
		while (!datatypes.isEmpty()) {
			boolean changed = false;
			Iterator<DataType> itr = datatypes.iterator();
			while (itr.hasNext()) {
				DataType dt = itr.next();
				List<JsonObject> entries = toJson(dt);
				if (entries == null) {
					continue; // waiting for dependencies to added first
				}
				itr.remove();
				for (JsonObject entry : entries) {
					json.add(entry);	
				}
				setSerialized(dt);
				changed = true;
			}
			
			if (!changed) {
				break; // we failed to remove any data types.
			}
		}

		for (DataType dt : datatypes ) {
			PrintMissing(dt);
		}

		printf("[PDBGEN] missing: %d\n", datatypes.size());
		return json;
	}
	
	public JsonArray buildForwardDeclarations(List<DataType> datatypes) {
		// some data that is common to all forward declarations
		JsonArray fields = new JsonArray();
		JsonArray options = new JsonArray();
		options.add("forwardref");
		
		JsonArray objs = new JsonArray();
		for (DataType dt : datatypes) {			
			JsonObject json = new JsonObject();

			// the forward declared type and the actual type need different IDs
			// to make things easy, we use the original id in the forward declaration
			// so we do not need to rewrite the all the references.
			// We create a new Id for the actual type, because nothing else references it.
			json.addProperty("id", GetId(dt));
			
			if (dt instanceof Enum) {
				json.addProperty("type", "LF_ENUM");
				json.addProperty("underlying_type", "0x0000");
			} else if (dt instanceof Union) {
				json.addProperty("type", "LF_UNION");
			} else if (dt instanceof Structure) {
				json.addProperty("type", "LF_STRUCTURE");
			} else {
				continue; // we do not need to forward declare this type
			}


			// PDB resolves forward declarations by looking for other types with the same unique name,
			// if it does not find one, it will match on name instead. 
			// I'm not sure if this can cause inconsistency if unique_name is not used...
			// To avoid issues, we use a uuid for the unique name to consistently match correctly.
			json.addProperty("name", dt.getName());
			json.addProperty("unique_name", GetFwdId(dt));
			json.addProperty("size", 0);
			json.add("options", options);
			json.add("fields", fields);
			
			objs.add(json);
			setSerialized(dt);
		}
		return objs;
	}

	public List<DataType> getAllDataTypes() {
		List<DataType> datatypes = new ArrayList<DataType>();
		// this function, despite its name, does not return all datatypes :(
		// we are going to have to go find the missing ones.
		currentProgram.getDataTypeManager().getAllDataTypes(datatypes);

		// for some reason, Ghidra does not include BitField DataTypes in getAllDataTypes, so we manually add them here. 
		Iterator<Composite> composites = currentProgram.getDataTypeManager().getAllComposites();
		while (composites.hasNext()) {
			Composite composite = composites.next();
			for (DataTypeComponent component :  composite.getComponents()) {
				if (!component.isBitFieldComponent()) continue;
				datatypes.add(component.getDataType());
			}
		}

		// functions are not apart of the data type manager apparently.
		Iterator<Function> functions = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			if (function.isThunk()) continue;
			if (function.isExternal()) continue;
			FunctionSignature signature = function.getSignature();
			if (signature instanceof FunctionDefinition) {
				datatypes.add((FunctionDefinition) signature);
				entrypoints.put(function.getEntryPoint(), (FunctionDefinition) signature);
			}
			for (Parameter param : function.getParameters()) {
				if (!datatypes.contains(param.getDataType())) {
					datatypes.add(param.getDataType());
				}
			}
		}

		// remove data types that we do not need to serialize for the pdb
		Iterator<DataType> itr = datatypes.iterator();
		while (itr.hasNext()) {
			DataType dt = itr.next();
			if (dt instanceof BuiltInDataType) {
				itr.remove();
			} else if (dt instanceof TypeDef) {
				itr.remove();
			}
		}
		return datatypes;
	}

	
	public List<Symbol> getAllSymbols() {
		List<Symbol> symbols = new ArrayList<Symbol>();
		for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(false)) {
			if (symbol.isExternal()) continue;
			symbols.add(symbol);
		}
		return symbols;
	}

	public JsonArray toJsonSymbols(List<Symbol> symbols) {
		JsonArray objs = new JsonArray();
		FunctionManager manager = currentProgram.getFunctionManager();
		for (Symbol symbol : symbols) {
			SymbolType stype = symbol.getSymbolType();
//			SourceType source = symbol.getSource();
			Address address = symbol.getAddress();

//			// We can do some interesting filtering based on where the symbol came from.
//			if (source == SourceType.ANALYSIS) {
//			} else if (source == SourceType.DEFAULT) {
//			} else if (source == SourceType.IMPORTED) {
//			} else if (source == SourceType.USER_DEFINED) {
//			}

			String name = symbol.getName(true);
			if (stype == SymbolType.CLASS) {
			} else if (stype == SymbolType.FUNCTION) {
				Function function = manager.getFunctionAt(address);
				// we rename any thunks to easily distinguish them from the actual functions
				if (function.isThunk() && !name.startsWith("thunk_")) {
					name = "thunk_"+name;
				}
				
				JsonObject json = new JsonObject();
				json.addProperty("type", "S_PUB32");
				json.addProperty("name", name);
				json.addProperty("address", address.getUnsignedOffset());
				json.addProperty("function", true);
				objs.add(json);

				if (function.isThunk()) continue;

				// for what ever reason, the ID of the FunctionSignature is different from when we dumps the types,
				// so we cache the original type, and use the function's address to find it now.
				FunctionDefinition definition = entrypoints.get(address);

				String id = GetId(definition);
//				printf("signature [%s] %s %s", definition.getName(), id, definition.getClass().getName());


//				// I dont have a good way of looking up the FunctionDefinition id from here. will probably need a refactor.
				Address start = function.getBody().getMinAddress();
				Address end = function.getBody().getMaxAddress();

				// S_GPROC32
				json = new JsonObject();
				json.addProperty("type", "S_GPROC32");
				json.addProperty("name", name);
				json.addProperty("address", start.getUnsignedOffset());
				json.addProperty("code_size", end.subtract(start)+1);
				json.addProperty("end", 0);
				json.addProperty("function_type", id);
				json.addProperty("debug_start", 0);
				json.addProperty("debug_end", 0);
				json.addProperty("parent", "0x0000");
				json.add("flags", new JsonArray());
				objs.add(json);
				
				json = new JsonObject();
				json.addProperty("type", "S_END");
				objs.add(json);

//				// S_PROCREF
//				fmt = "{\"type\": \"S_PROCREF\", \"name\": \"%s\", \"address\": %d, \"code_size\": \"%d\", \"function_type\": \"%s\", \"debug_start\": %d, \"debug_end\": %d, \"parent\": \"%s\", \"flags\": []}";
//				lines.add(String.format(fmt,  name, start.getUnsignedOffset(), end.subtract(start)+1, id, 0, 0, "0x0000"));
			} else if (stype == SymbolType.GLOBAL || stype == SymbolType.GLOBAL_VAR) {
				JsonObject json = new JsonObject();
				json.addProperty("type", "S_PUB32");
				json.addProperty("name", name);
				json.addProperty("adderss", address.getUnsignedOffset());
				json.addProperty("function", false);
				objs.add(json);

			} else if (stype == SymbolType.LABEL) {
			} else if (stype == SymbolType.CLASS) {
			} else if (stype == SymbolType.LIBRARY) {
			} else if (stype == SymbolType.LOCAL_VAR) {
			} else if (stype == SymbolType.NAMESPACE) {
			} else if (stype == SymbolType.PARAMETER) {
			} else {
				// unknown symbol type
			}
		}
		return objs;
	}

	public void initializeTypeDefs() {
		// map Ghidra built-in types that are predefined by CodeView
		// these do not have a UniversalID so we reference them by their name instead.
		// note: name may not be unique, but its all i have found so far.
		typedefs.put("null", "0x0000"); // NULLLEAF 
		typedefs.put("void", "0x0003");
		typedefs.put("bool", "0x0030");
		typedefs.put("byte", "0x0069");
		typedefs.put("sbyte", "0x0068");
		typedefs.put("char", "0x0070");
		typedefs.put("uchar", "0x0020");
		typedefs.put("wchar_t", "0x0071");
		typedefs.put("short", "0x0011");
		typedefs.put("ushort", "0x0021");
		typedefs.put("int", "0x0074");
		typedefs.put("uint", "0x0075");
		typedefs.put("long", "0x0012");
		typedefs.put("ulong", "0x0022");
		typedefs.put("longlong", "0x0076");
		typedefs.put("ulonglong", "0x0077");
		typedefs.put("word", "0x0073");
		typedefs.put("dword", "0x0075");
		typedefs.put("qword", "0x0077");
		typedefs.put("float", "0x0040");
		typedefs.put("double", "0x0041");
		typedefs.put("float10", "0x0042")
		// pointer types
		typedefs.put("void *", "0x0603");
		typedefs.put("short *", "0x0611");
		typedefs.put("long *", "0x0612");
		typedefs.put("longlong *", "0x0613");
		typedefs.put("__int64 *", "0x0613");
		typedefs.put("uchar *", "0x0620");
		typedefs.put("ulong *", "0x0622");
		typedefs.put("ulonglong *", "0x0623");
		typedefs.put("char *", "0x0670");
		typedefs.put("wchar_t *", "0x0671");
		typedefs.put("int *", "0x0674");
		typedefs.put("char16_t *", "0x067A");
		typedefs.put("char32_t *", "0x067B");
		// I haven't seen these yet
		typedefs.put("float *", "0x0640");
		typedefs.put("double *", "0x0641");
		typedefs.put("float10 *", "0x0642");
		
		for (String id : typedefs.values()) {
			serialized.add(id);
		}

		typedefs.put("undefined", "byte");
		typedefs.put("undefined1", "byte");
		typedefs.put("undefined2", "ushort");
		typedefs.put("undefined4", "uint");
		typedefs.put("undefined8", "ulonglong");
		typedefs.put("ImageBaseOffset32", "uint");
		typedefs.put('float8', 'double')
		typedefs.put('float8 *', 'double *')
		// these types have a valid UniversalID so we reference that instead
		// faking some objects that are not defined for some reason....
		typedefs.put("GUID", "void");
		typedefs.put("string", "char *");
		typedefs.put("unicode", "wchar_t *"); // as far as I can tell, unicode is defined as 16bit codepoints
		typedefs.put("unicode32", "char32_t *");
		Map<String, String> names = new HashMap<String, String>();
		names.put("/undefined", "void");
		names.put("/__int64", "longlong"); 
		names.put("/__uint64", "ulonglong");

		for (String key : names.keySet()) {
			DataType dt = currentProgram.getDataTypeManager().getDataType(key);
			if (dt == null) continue;
			String value = dt.getUniversalID().toString();
			typedefs.put(value, names.get(key));
		}

		// pre-populate typedef information so we can map typedefs as we process the rest of the types 
		var allTypes = currentProgram.getDataTypeManager().getAllDataTypes();
		while (allTypes.hasNext()) {
			DataType dt = allTypes.next();
			if (!(dt instanceof TypeDef)) {
				continue;
			}

			var typedef = (TypeDef) dt;
			// we use GetIdUnmapped because we want the "typedef type" id, not "original type" id. 
			String key = GetIdUnmapped(typedef);
			String value = GetIdUnmapped(typedef.getDataType());
			typedefs.put(key, value);
		}
	}
	
	public static List<String> readAll(InputStream in) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
		List<String> lines = new ArrayList<String>();
		while (reader.ready()) {
			lines.add(reader.readLine());
		}
		return lines;
	}
	
	public void run() throws Exception {
		// setup typedefs so we can map to basic types
		initializeTypeDefs();

		JsonObject json = new JsonObject();
		
		// Now serialize all the data types (in dependency order)
		json.add("types", toJson(getAllDataTypes()));
		json.add("symbols", toJsonSymbols(getAllSymbols()));

		typedefs.clear();
		serialized.clear();
		forwardDeclared.clear();

		// Ghidra has unhelpfully set the path to \C:\\Something\ this gives as a normal c:\\Something
		String exepath = Path.fromPathString(currentProgram.getExecutablePath()).toString();
		printf("executable: %s\n", exepath);
		String output = FilenameUtils.removeExtension(exepath).concat(".pdb");
		String jsonpath = FilenameUtils.removeExtension(exepath).concat(".json");
		
		output = "c:\\temp\\vmrest.pdb";
		jsonpath = "c:\\temp\\vmrest.json";
		
		FileWriter w = new FileWriter(jsonpath);
		w.write(json.toString());
		w.close();
		
		// simple configurable path
		// Ghidra will cache the default value here, and it will prefer its internal cached version over our default path :(.
//		output = askString("location to save", "select a location to save the output pdb", output);
//		
		ProcessBuilder pdbgen = new ProcessBuilder();
		pdbgen.command("pdbgen.exe", exepath, "-", "--output", output);
		
		Process proc = pdbgen.start();
		PrintWriter stdin = new PrintWriter(proc.getOutputStream());
		stdin.write(json.toString());
		stdin.close();
		proc.waitFor();
		for (String line : readAll(proc.getInputStream())) {
			println(line);
		}
		
		for (String line : readAll(proc.getErrorStream())) {
			printerr(line);
		}
		
		return;
	}
}