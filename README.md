# PdbGen

Generate a PDB from Ghidra

This project is still very much a WIP, but the basic components should be usable.

### Quickstart

1. Download the latest version from [github releases](https://github.com/wandel/pdbgen/releases)
1. Copy `assets/PdbGen.java` into your ghidra_scripts folder (`%USERPROFILE%/ghidra_scripts`).
1. Copy `assets/pdbgen.exe` into a folder on your PATH
1. Run the pdbgen script via Ghidra's Script Manager
   1. The first time it runs, it will ask for an output location for the generated pdbs.
   1. The pdb will be saved in a symsrv compatible path using that output location as the base directory.
1. Update your \_NT_SYMBOL_PATH / WinDbgX settings with the folder you selected when you first ran the script
   1. make sure it is before any `cache*` entries, otherwise WinDbgX will not reload from the generated pdb.
1. Open WinDbgX and run "reload /f" to load the new pdb.
1. Once you have made changes in Ghidra, regenerate the pdb file using one of the following:
   1. Ctrl-G Keybind
   1. Tools -> Generate PDB
   1. Script Manager
1. Reload the new symbols in WinDbgX to load the changes
   1. `.reload /f <module>`

## Notes

1. If WinDbgX is not picking up the new symbols, ensure that there is no `cache*` entry before the generated symbol location.
   1. `cache*` tells WinDbgX to store a copy of the .pdb file at the given location.
      1. WinDbgX will not go back to check for a newer version.
      1. this applies to all symbols fetched from sorces processed after this entry.
   1. The default location for WinDbgX cache is `C:\ProgramData\Dbg\Sym`.
1. PDBGen will ask for a directory to store its generated pdbs in
   1. if you need to change this in the future, edit the file mentioned in the console output
   1. you can override this by setting the `OVERRIDE_SYMBOL_OUTPUT_PATH` value in the script.
1. Currently only global function symbols and data types are currently generated.
   1. dt <module!typename> <address>
   1. x <module!symbolname>
   1. function names should be resolved in the callstack.
1. If the CodeView entry in the DEBUG_DATA_DIRECTORY has been removed, it will fail to generate a pdb
   1. This is because the path to pdb is dictated by the `signature`/`guid` and `age` values in this entry.
   1. WinDbgX will use the files TimeDateStamp and SizeOfImage to fetch a legacy .dbg file, which I would like to support in the future.
1. You can dump a pdb using llvm's pdbutil tool: `llvm-pdbutil.exe dump --all <pdbpath>`
1. We do not need the original binary for Ghidra (it has all the information already)
   1. however I would like to support IDA, which AFAIK discards the pe headers after importing.

## How to Build

```sh
# You will require a c++17 compliant compiler
git clone --config core.autocrlf=false --branch llvmorg-16.0.0 --single-branch https://github.com/llvm/llvm-project.git
git clone https://github.com/wandel/pdbgen.git --branch develop
git -C llvm-project apply ../pdbgen/llvm-debuginfo.patch  # fix a bug in GSIStreamBuilder
cmake -B llvm-project/build -S llvm-project/llvm -Thost=x64
cmake --build llvm-project/build --target llvm-pdbutil # will take 10mins or so
cmake -B pdbgen/build -S pdbgen/core -DLLVM_DIR=../../llvm-project/build/lib/cmake/llvm -Thost=x64
cmake --build pdbgen/build
```

## To Do

- [ ] Clean this mess up
- [ ] Add symbols for function arguments
- [ ] Add symbols for local variables in functions
- [ ] Support Strings
- [ ] Build with Clang instead of Visual Studio 2019
- [ ] Support building & running on linux
- [ ] Support IDA
- [ ] Avoid requiring the original executable file

## Thanks

1. https://github.com/llvm/llvm-project
1. https://github.com/Mixaill/FakePDB
