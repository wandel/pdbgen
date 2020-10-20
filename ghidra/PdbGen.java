//Generates a PDB containing public symbols and type information derived from ghidra's database
//@author Brett Wandel
//@category Windows
//@keybinding ctrl G
//@menupath Tools.Generate PDB
//@toolbar 

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.util.Strings;

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
	
	private String dump(Pointer x) {
		if (!isSerialized(x.getDataType())) return null;
		String fmt = "{\"type\":\"LF_POINTER\", \"id\": \"%s\", \"referent_type\": \"%s\"}";
		return String.format(fmt, GetId(x), GetId(x.getDataType()));
	}

	private String dump(Array x) {
		if (!isSerialized(x.getDataType())) return null;
		String fmt = "{\"type\":\"LF_ARRAY\", \"id\": \"%s\", \"index_type\": \"0x0077\", \"element_type\": \"%s\", \"size\": %d}";
		return String.format(fmt, GetId(x), GetId(x.getDataType()), x.getLength());
	}
	
	private String dump(Union x) {
		List<String> members = new ArrayList<String>();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) return null;
			String fmt = "{\"type\": \"LF_MEMBER\", \"name\": \"%s\", \"type_id\": \"%s\", \"offset\": %d, \"attributes\": []}";
			members.add(String.format(fmt, dt.getFieldName(), GetId(dt.getDataType()), dt.getOffset()));
		}
		
		String fmt = "{\"type\": \"LF_UNION\", \"id\": \"%s\", \"name\": \"%s\", \"unique_name\":\"%s\", \"size\": %d, \"fields\": [%s], \"options\": []}";
		return String.format(fmt, GetFwdId(x), x.getName(),  GetFwdId(x), x.getLength(), Strings.join(members, ','));
	}

	private String dump(Enum x) {
		List<String> values = new ArrayList<String>();
		for (long value : x.getValues()) {
			String fmt = "{\"name\": \"%s\", \"value\": %d}";
			values.add(String.format(fmt,  x.getName(value), value));
		}
		String fmt = "{\"type\":\"LF_ENUM\", \"id\": \"%s\", \"size\": %d, \"underlying_type\": \"0x0074\", \"name\": \"%s\", \"unique_name\": \"%s\", \"options\": [], \"fields\": [%s]}";
		return String.format(fmt, GetFwdId(x), x.getLength(), x.getName(),  GetFwdId(x), Strings.join(values, ','));
	}

	private String dump(Structure x) {
		List<String> fields = new ArrayList<String>();
		for (DataTypeComponent dt : x.getComponents()) {
			if (!isSerialized(dt.getDataType())) return null;
			if (dt.isBitFieldComponent()) {
				// TODO implement this
				// BitFieldDataType bfdt = (BitFieldDataType) dt.getDataType();
				String fmt = "{\"type\": \"LF_MEMBER\", \"name\": \"%s\", \"type_id\": \"%s\", \"offset\": %d, \"attributes\": []}";
				fields.add(String.format(fmt, dt.getFieldName(), GetId(dt.getDataType()), dt.getOffset()));
			} else {
				String fmt = "{\"type\": \"LF_MEMBER\", \"name\": \"%s\", \"type_id\": \"%s\", \"offset\": %d, \"attributes\": []}";
				fields.add(String.format(fmt, dt.getFieldName(), GetId(dt.getDataType()), dt.getOffset()));
			}
		}

		String fmt = "{\"type\":\"LF_STRUCTURE\", \"id\": \"%s\", \"name\":\"%s\", \"unique_name\":\"%s\", \"size\": %d, \"options\":[], \"fields\": [%s]}";
		return String.format(fmt, GetFwdId(x), x.getName(), GetFwdId(x), x.getLength(), Strings.join(fields, ','));
	}

//	No longer required, we map typedefs to their underlying type before processing the rest of the types
//	I have not found any codeview type for typedefs, so we map the types (AFAIK like the linker does).
//	private static String dump(TypeDef x) {
//		return String.format("<typedef id=\"%s\" name=\"%s\" type=\"%s\" />", GetId(x),  x.getName(), GetId(x.getDataType()));
//		String fmt = "{\"type\": \"TYPEDEF\", \"id\": \"%s\", \"name\": \"%s\", \"target\": \"%s\"}";
//		return String.format(fmt, GetId(x), x.getName(), GetId(x.getDataType()));
//		fakeUIDs.put(x.getUniversalID().toString(), GetId(x.getDataType()));
//		return "";
//	}
	
	private String dump(BitFieldDataType x) {
		if (!isSerialized(x.getBaseDataType())) return null;
		String fmt = "{\"type\": \"LF_BITFIELD\", \"id\": \"%s\", \"type_id\": \"%s\", \"bit_offset\": %d, \"bit_size\": %d}";
		return String.format(fmt, GetId(x), GetId(x.getBaseDataType()), x.getBitOffset(), x.getBitSize());
	}
	
	private List<String> dump(FunctionDefinition x) {
		if (!isSerialized(x.getReturnType())) return null;
		List<String> parameters = new ArrayList<String>();
		for (ParameterDefinition p : x.getArguments()) {
			if (!isSerialized(p.getDataType())) return null;
			parameters.add('"'+GetId(p.getDataType())+'"');
		}

		List<String> entries = new ArrayList<String>();
		// we need to emit a LF_PROCEDURE before the LF_FUNC_ID because PDB requires strict ordering.
		String fmt = "{\"type\":\"LF_PROCEDURE\", \"id\": \"%s\", \"name\": \"%s\", \"return_type\": \"%s\", \"calling_convention\": \"%s\", \"options\": [], \"parameters\": [%s]}";
		entries.add(String.format(fmt, GetId(x), x.getName(), GetId(x.getReturnType()), x.getGenericCallingConvention().toString(), Strings.join(parameters, ',')));

		// We are creating a new id here just so it flows through our pipeline correctly with the rest of the types.
		String tmpId = UUID.randomUUID().toString();
		fmt = "{\"type\": \"LF_FUNC_ID\", \"id\": \"%s\", \"name\": \"%s\", \"function_type\": \"%s\", \"parent_scope\":\"%s\"}";
		entries.add(String.format(fmt, tmpId, x.getName(), GetId(x), "0x0000"));

		return entries;
	}

	private List<String> toJson(DataType dt) {
		if (dt instanceof FunctionDefinition) {
			return dump((FunctionDefinition) dt);
		}
		
		List<String> entries = new ArrayList<String>();
		String line = null;
		if (dt instanceof Pointer) {
			line = dump((Pointer) dt);
		} else if (dt instanceof BitFieldDataType) {
			line = dump((BitFieldDataType) dt);
		} else if (dt instanceof Array) {
			line = dump((Array) dt);
		} else if (dt instanceof Union) {
			line = dump((Union) dt);
		} else if (dt instanceof Enum) {
			line = dump((Enum) dt);
		} else if (dt instanceof Structure) {
			line = dump((Structure) dt);
		} else {
			printf("Unknown Type: id=%s, name=%s, class=%s", GetId(dt), dt.getName(), dt.getClass().getName());
			return entries;
		}

		if (line == null) {
			return null;
		}
		
		entries.add(line);
		return entries;
	}

	public void PrintMissing(DataType dt0, String msg, DataType dt1) {
		if (isSerialized(dt1)) return;
		printf("missing: %s %s %s\n", dt0.getName(), msg, GetId(dt1));
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
			printf("Unknown Type:", dt);
		}
		return;
	}
	

	public List<String> toJson(List<DataType> datatypes) {
		// Build forward declarations for everything, basically because I'm lazy.
		// We should only need to add forward declarations for data types that have cyclic dependencies.
		List<String> lines = buildForwardDeclarations(datatypes);

		// A naive ordered serialization. We continually iterate through the list,
		// serializing data types only once they have had all their dependencies serialized.
		// we stop looping over the list once we fail to serialize at least one data type.
		// Any data types that are missing dependent types will be left in the input list.
		while (!datatypes.isEmpty()) {
			boolean changed = false;
			Iterator<DataType> itr = datatypes.iterator();
			while (itr.hasNext()) {
				DataType dt = itr.next();
				List<String> entries = toJson(dt);
				if (entries == null) {
					continue; // waiting for dependencies to added first
				}
				itr.remove();
				lines.addAll(entries);
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

		printf("missing: %d\n", datatypes.size());
		return lines;
	}
	
	public List<String> buildForwardDeclarations(List<DataType> datatypes) {
		List<String> lines = new ArrayList<String>();
		for (DataType dt : datatypes) {			

			String extra = "";
			if (dt instanceof Enum) {
				extra = "\"type\": \"LF_ENUM\", \"underlying_type\": \"0x0000\"";
			} else if (dt instanceof Union) {
				extra = "\"type\": \"LF_UNION\"";
			} else if (dt instanceof Structure) {
				extra = "\"type\": \"LF_STRUCTURE\"";
			} else {
				continue; // we do not need to forward declare this type
			}

			// the forward declared type and the actual type need different IDs
			// to make things easy, we use the original id in the forward declaration
			// so we do not need to rewrite the all the references.
			// We create a new Id for the actual type, because nothing else references it.
			String id = GetId(dt);
			String alias = GetFwdId(dt);

			// PDB resolves forward declarations by looking for other types with the same unique name,
			// if it does not find one, it will match on name instead. 
			// I'm not sure if this can cause inconsistency if unique_name is not used...
			// To avoid issues, we use a uuid for the unique name to consistently match correctly.
			String fmt = "{\"id\": \"%s\", %s, \"name\": \"%s\", \"unique_name\": \"%s\", \"size\": 0, \"options\": [\"forwardref\"], \"fields\":[]}";
			lines.add(String.format(fmt, id, extra, dt.getName(), alias)); // id is also the name
			setSerialized(dt);
		}
		return lines;
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

	public List<String> toJsonSymbols(List<Symbol> symbols) {
		List<String> lines = new ArrayList<String>();
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

			if (stype == SymbolType.CLASS) {
			} else if (stype == SymbolType.FUNCTION) {
				Function function = manager.getFunctionAt(address);
				if (function.isThunk()) continue;
				String fmt = "{\"type\": \"S_PUB32\", \"name\": \"%s\", \"address\": %d, \"function\": true}";
				lines.add(String.format(fmt, symbol.getName(true), address.getUnsignedOffset()));

				FunctionSignature signature = function.getSignature();
				String id = GetId((FunctionDefinition) signature);
//				// I dont have a good way of looking up the FunctionDefinition id from here. will probably need a refactor.
				Address start = function.getBody().getMinAddress();
				Address end = function.getBody().getMaxAddress();
				// S_GPROC32
				fmt = "{\"type\": \"S_GPROC32\", \"name\": \"%s\", \"address\": \"%s\", \"code_size\": \"%d\", \"function_type\": \"%s\", \"debug_start\": %d, \"debug_end\": %d, \"parent\": \"%s\", \"flags\": []}";
				lines.add(String.format(fmt,  symbol.getName(), start.getUnsignedOffset(), end.subtract(start)+1, id, 0, 0, "0x0000"));
//				
//				// S_PROCREF
				fmt = "{\"type\": \"S_PROCREF\", \"name\": \"%s\", \"address\": \"%s\", \"code_size\": \"%d\", \"function_type\": \"%s\", \"debug_start\": %d, \"debug_end\": %d, \"parent\": \"%s\", \"flags\": []}";
				lines.add(String.format(fmt,  symbol.getName(), start.getUnsignedOffset(), end.subtract(start)+1, id, 0, 0, "0x0000"));
			} else if (stype == SymbolType.GLOBAL) {
				String fmt = "{\"type\": \"S_PUB32\", \"name\": \"%s\", \"address\": %d, \"function\": false}";
				lines.add(String.format(fmt, symbol.getName(), address.getUnsignedOffset()));
			} else if (stype == SymbolType.GLOBAL_VAR) {
				String fmt = "{\"type\": \"S_PUB32\", \"name\": \"%s\", \"address\": %d, \"function\": false}";
				lines.add(String.format(fmt, symbol.getName(), address.getUnsignedOffset()));
			} else if (stype == SymbolType.LABEL) {
			} else if (stype == SymbolType.LIBRARY) {
			} else if (stype == SymbolType.LOCAL_VAR) {
			} else if (stype == SymbolType.NAMESPACE) {
			} else if (stype == SymbolType.PARAMETER) {
			} else {
				// unknown symbol type
			}
		}
		return lines;
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
		typedefs.put("float", "0x0640");
		typedefs.put("double", "0x0641");
		
		for (String id : typedefs.values()) {
			serialized.add(id);
		}

		typedefs.put("undefined1", "byte");
		typedefs.put("undefined2", "ushort");
		typedefs.put("undefined4", "uint");
		typedefs.put("undefined8", "ulonglong");
		typedefs.put("ImageBaseOffset32", "uint");
		// these types have a valid UniversalID so we reference that instead
		// faking some objects that are not defined for some reason....
		typedefs.put("GUID", "void");
		typedefs.put("string", "void");
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
	
	public void run() throws Exception {
		// setup typedefs so we can map to basic types
		initializeTypeDefs();

		// Now serialize all the data types (in dependency order)
		List<String> datatypes = toJson(getAllDataTypes());
		List<String> symbols = toJsonSymbols(getAllSymbols());		
		String fmt = "{\"types\": [%s], \"symbols\": [%s]}";
		String json = String.format(fmt, Strings.join(datatypes, ','), Strings.join(symbols, ','));

		// simple configurable path
		// Ghidra will cache the default value here, and it will prefer its internal cached vesion over our default path :(.
		String path = currentProgram.getExecutablePath() + ".json";
		path = askString("location to save", "select a location to save the output json", path);
		PrintWriter w = new PrintWriter(path);
		w.write(json);
		w.close();

		typedefs.clear();
		serialized.clear();
		forwardDeclared.clear();
		
		return;
	}
}