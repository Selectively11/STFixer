@echo off
setlocal

set "VSTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "CL=%VSTOOLS%\bin\Hostx64\x64\cl.exe"
set "LINK=%VSTOOLS%\bin\Hostx64\x64\link.exe"
set "INCLUDE=%VSTOOLS%\include"
set "LIB=%VSTOOLS%\lib\x64"

rem Windows SDK
set "WINSDK=C:\Program Files (x86)\Windows Kits\10"
set "WINSDKVER=10.0.26100.0"
set "INCLUDE=%INCLUDE%;%WINSDK%\Include\%WINSDKVER%\ucrt;%WINSDK%\Include\%WINSDKVER%\um;%WINSDK%\Include\%WINSDKVER%\shared"
set "LIB=%LIB%;%WINSDK%\Lib\%WINSDKVER%\ucrt\x64;%WINSDK%\Lib\%WINSDKVER%\um\x64"

echo Building stella_fallback.dll (x64)...

"%CL%" /nologo /O1 /GS- /W3 /c /Fo"stella_fallback.obj" stella_fallback.c /I"%VSTOOLS%\include" /I"%WINSDK%\Include\%WINSDKVER%\ucrt" /I"%WINSDK%\Include\%WINSDKVER%\um" /I"%WINSDK%\Include\%WINSDKVER%\shared"
if errorlevel 1 goto :fail

"%LINK%" /nologo /DLL /OUT:stella_fallback.dll /DEF:stella_fallback.def stella_fallback.obj winhttp.lib kernel32.lib /LIBPATH:"%VSTOOLS%\lib\x64" /LIBPATH:"%WINSDK%\Lib\%WINSDKVER%\ucrt\x64" /LIBPATH:"%WINSDK%\Lib\%WINSDKVER%\um\x64" /NODEFAULTLIB:libcmt.lib /DEFAULTLIB:msvcrt.lib /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF
if errorlevel 1 goto :fail

echo.
echo Build successful!
echo Output: stella_fallback.dll
dir stella_fallback.dll
goto :end

:fail
echo.
echo BUILD FAILED
exit /b 1

:end
endlocal
