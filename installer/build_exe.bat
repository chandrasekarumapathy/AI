@echo off
REM BigSleep ASM — Build Windows EXE
REM Run from project root: installer\build_exe.bat

echo.
echo ============================================================
echo   BigSleep ASM — PyInstaller Build
echo ============================================================
echo.

where python >nul 2>&1 || (echo Python not found && exit /b 1)

echo [1/3] Installing build dependencies...
python -m pip install --quiet pyinstaller pyinstaller-hooks-contrib

echo [2/3] Running PyInstaller...
python -m PyInstaller bigsleep.spec --clean --noconfirm

echo [3/3] Done.
echo.
echo Output: dist\BigSleepASM\BigSleepASM.exe
echo.
echo To run:
echo   cd dist\BigSleepASM
echo   BigSleepASM.exe setup
echo   BigSleepASM.exe
echo.
