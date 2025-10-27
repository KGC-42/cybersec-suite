import os
import sys
import subprocess
import shutil
from pathlib import Path

def install_pyinstaller():
    """Install PyInstaller if not present"""
    try:
        import PyInstaller
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def create_spec_file():
    """Create PyInstaller spec file"""
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['agent.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('config.py', '.'),
        ('scanner.py', '.'),
    ],
    hiddenimports=[
        'clamd',
        'requests',
        'psutil',
        'json',
        'time',
        'os',
        'sys',
        'threading',
        'logging',
        'datetime',
        'socket',
        'subprocess',
        'platform',
        'hashlib',
        'urllib3',
        'certifi',
        'charset_normalizer',
        'idna',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CyberSecAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt'
)
'''
    
    with open('cybersec_agent.spec', 'w') as f:
        f.write(spec_content)

def create_version_info():
    """Create version info file for Windows executable"""
    version_info = '''
VSVersionInfo(
  ffi=FixedFileInfo(
filevers=(1, 0, 0, 0),
prodvers=(1, 0, 0, 0),
mask=0x3f,
flags=0x0,
OS=0x40004,
fileType=0x1,
subtype=0x0,
date=(0, 0)
),
  kids=[
StringFileInfo(
  [
  StringTable(
    u'040904B0',
    [StringStruct(u'CompanyName', u'CyberSec Suite'),
    StringStruct(u'FileDescription', u'CyberSec Agent'),
    StringStruct(u'FileVersion', u'1.0.0.0'),
    StringStruct(u'InternalName', u'CyberSecAgent'),
    StringStruct(u'LegalCopyright', u'Copyright 2024'),
    StringStruct(u'OriginalFilename', u'CyberSecAgent.exe'),
    StringStruct(u'ProductName', u'CyberSec Suite Agent'),
    StringStruct(u'ProductVersion', u'1.0.0.0')])
  ]), 
VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
    
    with open('version_info.txt', 'w') as f:
        f.write(version_info)

def create_readme():
    """Create installation README"""
    readme_content = '''
# CyberSec Suite Agent - Installation Instructions

## Overview
This package contains the CyberSec Suite Agent executable for Windows.

## Installation

### Option 1: Direct Run
1. Download CyberSecAgent.exe
2. Double-click to run (no installation required)
3. Agent will start automatically

### Option 2: Service Installation
1. Open Command Prompt as Administrator
2. Navigate to the folder containing CyberSecAgent.exe
3. Run: CyberSecAgent.exe --install-service
4. Start service: net start CyberSecAgent

## Configuration
1. The agent will create a config file on first run
2. Edit the configuration as needed:
   - Server endpoint URLs
   - Scan intervals
   - Log levels
   - Network settings

## Requirements
- Windows 7 or later (64-bit recommended)
- Internet connection for updates
- Administrator privileges (for full functionality)

## Features
- Real-time malware scanning
- System monitoring
- Network security assessment
- Automated threat reporting
- Centralized management

## Uninstallation
1. Stop the service: net stop CyberSecAgent
2. Remove service: CyberSecAgent.exe --remove-service
3. Delete the executable and config files

## Support
For support and documentation, visit: https://cybersec-suite.com

## Version
Version: 1.0.0
Build Date: 2024
'''
    
    with open('README_INSTALL.txt', 'w') as f:
        f.write(readme_content)

def is_running_as_exe():
    """Check if running as compiled executable or Python script"""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

def get_resource_path(relative_path):
    """Get absolute path to resource for both .py and .exe"""
    if is_running_as_exe():
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def build_installer():
    """Build the Windows installer using PyInstaller"""
    try:
        # Install PyInstaller if needed
        install_pyinstaller()
        
        # Import after installation
        import PyInstaller.__main__
        
        # Create necessary files
        create_spec_file()
        create_version_info()
        create_readme()
        
        # Ensure dist directory exists
        os.makedirs('dist', exist_ok=True)
        
        # Check required files exist
        required_files = ['agent.py', 'scanner.py', 'config.py']
        missing_files = [f for f in required_files if not os.path.exists(f)]
        
        if missing_files:
            print(f"Error: Missing required files: {missing_files}")
            return False
        
        print("Building installer with PyInstaller...")
        
        # Run PyInstaller with spec file
        PyInstaller.__main__.run([
            'cybersec_agent.spec',
            '--clean',
            '--noconfirm'
        ])
        
        # Copy README to dist folder
        if os.path.exists('dist/CyberSecAgent.exe'):
            shutil.copy2('README_INSTALL.txt', 'dist/')
            print("✓ Installer built successfully!")
            print("✓ Output location: dist/CyberSecAgent.exe")
            print("✓ Installation instructions: dist/README_INSTALL.txt")
            return True
        else:
            print("✗ Build failed - executable not found")
            return False
            
    except Exception as e:
        print(f"Build failed with error: {e}")
        return False

def clean_build_files():
    """Clean up temporary build files"""
    cleanup_items = [
        'build',
        '__pycache__',
        'cybersec_agent.spec',
        'version_info.txt'
    ]
    
    for item in cleanup_items:
        if os.path.exists(item):
            if os.path.isdir(item):
                shutil.rmtree(item)
            else:
                os.remove(item)
    
    print("✓ Build files cleaned up")

def main():
    """Main installer function"""
    print("CyberSec Suite Agent - Installer Builder")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--clean':
            clean_build_files()
            return
        elif sys.argv[1] == '--test':
            print(f"Running as executable: {is_running_as_exe()}")
            print(f"Resource path test: {get_resource_path('config.py')}")
            return
    
    # Build the installer
    success = build_installer()
    
    if success:
        print("\nBuild completed successfully!")
        print("You can now distribute dist/CyberSecAgent.exe")
        
        # Ask if user wants to clean up
        clean = input("\nClean up build files? (y/n): ").lower().strip()
        if clean == 'y':
            clean_build_files()
    else:
        print("\nBuild failed. Check the error messages above.")

if __name__ == "__main__":
    main()