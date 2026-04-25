# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds BigSleepASM.exe (single folder or one-file).

Build:
    pip install pyinstaller
    pyinstaller bigsleep.spec

Output: dist/BigSleepASM/BigSleepASM.exe   (onedir, faster startup)
        dist/BigSleepASM.exe               (onefile, if onefile=True below)
"""
from PyInstaller.utils.hooks import collect_submodules, collect_data_files
import sys

ONE_FILE = False   # Set True for single .exe (slower startup, easier to distribute)

block_cipher = None

# Collect dynamic imports from fastapi, uvicorn, starlette, aiosqlite
hidden_imports = (
    collect_submodules("fastapi")
    + collect_submodules("uvicorn")
    + collect_submodules("starlette")
    + collect_submodules("aiosqlite")
    + collect_submodules("psutil")
    + collect_submodules("pydantic")
    + [
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "asyncio",
        "email.mime.text",
        "email.mime.multipart",
        "hashlib",
        "hmac",
        "sqlite3",
        "winreg",   # Windows registry (ignored on non-Windows)
        "win32api",
        "win32con",
    ]
)

datas = [
    ("dashboard", "dashboard"),          # HTML dashboard
    ("config/config.yaml", "config"),    # Default config
    ("src", "src"),                      # Python source (needed for dynamic imports)
]

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["matplotlib", "numpy", "pandas", "PIL", "tkinter", "test"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if ONE_FILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.zipfiles, a.datas,
        name="BigSleepASM",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        console=True,
        icon=None,
    )
else:
    exe = EXE(
        pyz, a.scripts,
        exclude_binaries=True,
        name="BigSleepASM",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        console=True,
        icon=None,
    )
    coll = COLLECT(
        exe, a.binaries, a.zipfiles, a.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name="BigSleepASM",
    )
