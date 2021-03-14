@ECHO OFF
SETLOCAL

IF NOT DEFINED GHIDRA (
    SET GHIDRA="C:\Program Files\Ghidra\support\analyzeHeadless.bat"
)

IF NOT DEFINED PDBGEN (
    SET PDBGEN="..\build\Debug\pdbgen.exe"
)

DEL /S /Q build32 build64
cmake -B build32 -S . -Thost=x86
cmake -B build64 -S . -Thost=x64

cmake --build ..\build
cmake --build build32
cmake --build build64

DEL /S /Q ghidra
MKDIR ghidra
CALL :ANALYZE example32, build32\Debug\example.exe
CALL :ANALYZE example64, build64\Debug\example.exe

CALL :BACKUP build32\Debug\example.pdb
CALL :BACKUP build64\Debug\example.pdb

CALL :GENERATE build32\Debug\example.exe
CALL :GENERATE build64\Debug\example.exe

EXIT /B %ERRORLEVEL%


:ANALYZE
CALL %GHIDRA% ghidra %~2 -import %~2 -overwrite -postScript PdbGen -scriptPath "../ghidra/"
EXIT /B %ERRORLEVEL%

:BACKUP
MOVE "%~1" "%~1.bck"
EXIT /B %ERRORLEVEL%


:GENERATE
%PDBGEN% "%~1"
EXIT /B %ERRORLEVEL%
