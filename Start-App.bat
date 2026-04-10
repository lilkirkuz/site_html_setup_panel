@echo off
setlocal

cd /d "%~dp0"

title Pay Web Creator

REM Prefer project-local Node.js if present; fallback to system Node.
if exist ".local\node-current\bin\node.exe" (
  set "PATH=%CD%\.local\node-current\bin;%PATH%"
)

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js not found. Install Node.js or keep .local\node-current in this project folder.
  pause
  exit /b 1
)

if not exist "node_modules\.bin" (
  call npm install
  if errorlevel 1 (
    echo npm install failed.
    pause
    exit /b 1
  )
)

start "" /b cmd /c "ping 127.0.0.1 -n 3 >nul && start http://localhost:3000"
call npm start
