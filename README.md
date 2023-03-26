# PdbGen
Generate a PDB from Ghidra

This project is still very much a WIP, but the basic components should be usable.

### Quickstart
1. download the latest version from [github releases](https://github.com/wandel/pdbgen/releases)
1. copy ```assets/PdbGen.java``` into your ghidra_scripts folder (```%USERPROFILE%/ghidra_scripts```).
1. Run the pdbgen script via Ghidra's Script Manager.
1. Run ```assets/pdbgen.exe <path/name.exe>```
1. The new pdb will be found at ```path/name.pdb```
1. Load your binary in windbg and it should automatically find the new pdb.
    1. Note: ensure windbg is not using a cached copy (`c:\ProgramData\Dbg\Sym\<name.exe>`).

## Notes
1. Currently only global function symbols and data types are currently generated.
    1. dt <module!typename> <address>
    1. x <module!symbolname>
    1. function names should be resolved in the callstack.
1. You can dump a pdb using llvm's pdbutil tool: ```llvm-pdbutil.exe dump --all <pdbpath>```
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
