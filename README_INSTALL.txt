
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
