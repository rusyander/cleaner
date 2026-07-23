@echo off
setlocal
rem ==== Build (if needed) and run in one command ====
cd /d "%~dp0"

if not exist "WindowsProcessCleaner.exe" (
  call "%~dp0build.bat"
  if errorlevel 1 exit /b 1
)

start "" "WindowsProcessCleaner.exe"
endlocal
