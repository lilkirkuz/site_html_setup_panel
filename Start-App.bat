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
  if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" (
    set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
  ) else (
    where winget >nul 2>nul
    if errorlevel 1 (
      echo Node.js not found and winget is unavailable.
      echo Install Node.js LTS manually or place a portable Node in .local\node-current.
      pause
      exit /b 1
    )

    echo Installing Node.js LTS...
    winget install --id OpenJS.NodeJS.LTS -e --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
      echo Automatic Node.js install failed.
      pause
      exit /b 1
    )
  )
)

where node >nul 2>nul
if errorlevel 1 (
  if exist "%LOCALAPPDATA%\Programs\nodejs\node.exe" (
    set "PATH=%LOCALAPPDATA%\Programs\nodejs;%PATH%"
  )
)

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is still not available after install.
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
