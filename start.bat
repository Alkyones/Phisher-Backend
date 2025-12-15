@echo off
echo Building backend server...
cd backend
go build -o bin/server.exe .

if %errorlevel% equ 0 (
    echo Backend built successfully
    echo Starting server on port 8080...
    bin\server.exe
) else (
    echo Build failed
    pause
)