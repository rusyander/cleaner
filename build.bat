@echo off
setlocal
rem ==== Windows Process Cleaner - build with the built-in Windows csc.exe ====
rem No installation required: .NET Framework ships with Windows.

set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo [ERROR] csc.exe of .NET Framework 4.x not found.
  echo Expected: %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
  exit /b 1
)

echo Compiler: %CSC%
echo Building WindowsProcessCleaner.exe ...

"%CSC%" /nologo /target:winexe /optimize+ /out:WindowsProcessCleaner.exe ^
  /win32manifest:app.manifest ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  /reference:System.Runtime.Serialization.dll ^
  ProcessCleaner.cs

if errorlevel 1 (
  echo.
  echo [ERROR] Build failed.
  exit /b 1
)

echo.
echo [OK] Done: %CD%\WindowsProcessCleaner.exe
endlocal
