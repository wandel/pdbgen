rmdir /s /q "c:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\example.pdb"
@REM ..\ttd\amd64\ttd.exe -out traces/original.out "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -c "x example!compare;q" A:\workspace\pdbgen\example\build32\debug\example.exe
..\ttd\amd64\ttd.exe -out traces/original.out "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -c "x example!compare;q" A:\workspace\pdbgen\example\build64\debug\example.exe
@REM rmdir /s /q "c:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\example.pdb"

