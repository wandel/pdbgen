# typedef
1. S_UDT
    1. name = name of the new type
    1. original type = `type index` of the original type
```c
 typedef struct _ExampleStruct ExampleStruct;
```
```
14700 | S_UDT [size = 24] `ExampleStruct`
    original type = 0x1008
```
# function
A fucntion will generate quite a few pdb entries:
1. S_PROCREF - A global symbole that points to the private S_GPROC32/S_LPROC32 symbol.
    1. name = the name function
    1. module = the module number it is in.
        1. note although modules start at index=0... this starts at 1
        1. that is: `S_PROCREF.module = ModuleIdx+1`
    1. offset = the number of bytes into the module stream the S_GPROC32/S_LPROC32 is located
    1. sum name = ???
1. S_PUB32
    1. name = the name of the function
    1. flags = should be set to `function`, indicating this symbol is for a function
    1. addr = the address the function located at

1. S_GPROC/S_LPROC32 - start of the private symbol block for this function
    1. parent = ??
    1. end = the offset into the module stream where the S_END for this block is located
    1. address = the address of the function
    1. code size = the number of bytes in the function body
    1. type = the `type index` of the function (basically its signature)
    1. debug start = ???
    1. debug end = ???
    1. flags = any flags associated with the function

1. S_FRAMEPROC
    1. size = size of the stack frame used by this function
    1. padding size = ?? amount padding required for stack alignment??
    1. offset to padding = ?? offset adjust the stack to skip the padding ??
    1. bytes of callee saved registers = ?? number of bytes used for non-volatile registers ??
    1. exception hander address = ?? address of the exception handler ??
    1. local fp reg = the register used for the local frame pointer
    1. param fp reg = the register used for parameters
    1. flags = any flags associated with the stack frame
        1. `secure checks` = ?? stack cookie ??
        1. `no stack order` = ??
        1. `opt speed` = ??
1. S_FRAMECOOKIE
    1. code offset = ?? offset into the stack where the cookie is stored ??
    1. register = ??
    1. kind = ?? the kind of check that is used ??
    1. flags = ?? any flags associated with the stack cookie??
1. S_REGREL32 - ?? a variable that is located on the stack ??
    1. type = `type index` of the object that is stored at this location on the stack
    1. register = ??
    1. offset = offset in the stack where the object is stored
1. S_END = indicates the end of the S_GPROC32 block

1. LF_FUNC_ID
    1. name = the name of the function
    1. type = `type index` of the function (basically its signature)
    1. parent scope = ??
1. LF_PROCEDURE
    1. return type = `type index` of the return type
    1. num args = number of arguments in the param list
    1. param list = `type index` of the parameter list
    1. options = ??
    1. calling conv = the calling convention of the function
        1. `cdecl`
1. LF_ARGLIST - this is list of the following
    1. name = name of the argument
    1. type = `type index` of the argument's type

### Notes:
    1. calling convention always make sense... for example:
        1. msvc seems to usually emit `cdecl` for x64 binaries.

```c
int main() {
  ExampleStruct tmp = {0};
  ExampleFunc(tmp);
  tmp.valid = true;
  ExampleFunc(tmp);

  ExampleEnum test = ExampleEnum0;
  std::cout << "enum: " << test << std::endl;

  return 0;
}
```
```
// Global Symbols
2928 | S_PROCREF [size = 20] `main`
    module = 1, sum name = 0, offset = 312
    

// Public Symbols
51448 | S_PUB32 [size = 20] `main`
    flags = function, addr = 0001:1280

// Symbols
312 | S_GPROC32 [size = 44] `main`
    parent = 0, end = 480, addr = 0001:1280, code size = 305
    type = `0x23DB (int (int, char**))`, debug start = 64, debug end = 279, flags = none
356 | S_FRAMEPROC [size = 32]
    size = 12440, padding size = 0, offset to padding = 0
    bytes of callee saved registers = 0, exception handler addr = 0000:0000
    local fp reg = RSP, param fp reg = RSP
    flags = secure checks | no stack order | opt speed
388 | S_FRAMECOOKIE [size = 12]
    code offset = 12416, Register = RSP, kind = xor stack ptr, flags = 0
400 | S_REGREL32 [size = 20] `argc`
    type = 0x0074 (int), register = RSP, offset = 12464
420 | S_REGREL32 [size = 20] `argv`
    type = 0x14BD (char**), register = RSP, offset = 12472
440 | S_REGREL32 [size = 20] `test`
    type = 0x1003 (ExampleEnum), register = RSP, offset = 4164
460 | S_REGREL32 [size = 20] `tmp`
    type = 0x1008 (_ExampleStruct), register = RSP, offset = 48
480 | S_END [size = 4]

// TPI Stream
0x14BD | LF_POINTER [size = 12, hash = 0x38811]
    referent = 0x0670 (char*), mode = pointer, opts = None, kind = ptr64
0x23DA | LF_ARGLIST [size = 16, hash = 0xAEC2]
    0x0074 (int): `int`
    0x14BD: `char**`
0x23DB | LF_PROCEDURE [size = 16, hash = 0x32431]
    return type = 0x0074 (int), # args = 2, param list = 0x23DA
    calling conv = cdecl, options = None

// IPI Stream
  0x1000 | LF_FUNC_ID [size = 20, hash = 0x4122]
           name = main, type = 0x23DB, parent scope = <no type>

```


# arrays
1. LF_ARRAY
    1. size = sizeof(element) * number of elements
    1. index type = `type index` of the type that is used for the index.
    1. element type = `type index` of the type that is used for the element


```c
int ExampleGlobalArray[1024];
```
```     
40 | S_PUB32 [size = 44] `?ExampleGlobalArray@@3PAHA`
    flags = none, addr = 0003:0384

0x1004 | LF_ARRAY [size = 16, hash = 0x29575]
    size: 4096, index type: 0x0023 (unsigned __int64), element type: 0x0074 (int)
```


# structures

```c
struct _ExampleStruct
{
    bool valid;
    int array[1024];
    _ExampleStruct *next;
};
```
```
0x1005 | LF_STRUCTURE [size = 60, hash = 0x32520] `_ExampleStruct`
    unique name: `.?AU_ExampleStruct@@`
    vtable: <no type>, base list: <no type>, field list: <no type>
    options: forward ref (-> 0x1008) | has unique name, sizeof 0

0x1006 | LF_POINTER [size = 12, hash = 0x1763A]
    referent = 0x1005, mode = pointer, opts = None, kind = ptr64

0x1007 | LF_FIELDLIST [size = 52, hash = 0x1A006]
    - LF_MEMBER [name = `valid`, Type = 0x0030 (bool), offset = 0, attrs = public]
    - LF_MEMBER [name = `array`, Type = 0x1004, offset = 4, attrs = public]
    - LF_MEMBER [name = `next`, Type = 0x1006, offset = 4104, attrs = public]

0x1008 | LF_STRUCTURE [size = 60, hash = 0x84E6] `_ExampleStruct`
    unique name: `.?AU_ExampleStruct@@`
    vtable: <no type>, base list: <no type>, field list: 0x1007
    options: has unique name, sizeof 4112
```

# globals
```c
int ExampleGlobalArray[1024];
```
```
14680 | S_GDATA32 [size = 36] `ExampleGlobalArray`
    type = 0x1004 (), addr = 0003:0384
```