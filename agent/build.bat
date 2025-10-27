@echo off
echo ========================================
echo CyberSec Agent - Building Installer
echo ========================================

echo.
echo [1/4] Cleaning old build files...
if exist dist rmdir /s /q dist
if exist build rmdir /s /q build

echo.
echo [2/4] Running PyInstaller...
pyinstaller --onefile --name CyberSecAgent --hidden-import=clamd --hidden-import=psutil --clean agent.py

echo.
echo [3/4] Checking output...
if exist dist\CyberSecAgent.exe (
    echo [SUCCESS] CyberSecAgent.exe created in dist folder!
) else (
    echo [FAILED] Build did not create .exe file
)

echo.
echo [4/4] Build complete!
pause