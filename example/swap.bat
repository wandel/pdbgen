@ECHO OFF

CALL :SWAP build32\Debug\example.pdb
CALL :SWAP build64\Debug\example.pdb

EXIT /B %ERRORLEVEL%

:SWAP
ECHO %~1
if EXIST "%~1.tmp" (
    echo Using Generated PDBs
    MOVE %~1 %~1.bck
    MOVE %~1.tmp %~1
) ELSE (
    echo Using Original PDBs
    MOVE %~1 %~1.tmp
    MOVE %~1.bck %~1
)
EXIT /B %ERRORLEVEL%