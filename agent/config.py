"""
CyberSec Suite Agent - Configuration
Handles all settings, paths, and environment variables.
"""
import os
from pathlib import Path

class Config:
    """Configuration for CyberSec Agent."""
    
    def __init__(self):
        # Backend API
        self.backend_url = os.getenv(
            "CYBERSEC_BACKEND_URL",
            "https://cybersec-backend-production.up.railway.app"
        )
        
        # API Key for agent authentication
        # Users will get this from the dashboard after logging in
        self.api_key = os.getenv(
            "CYBERSEC_API_KEY",
            None  # Will prompt user if not set
        )
        
        # Timing intervals (in seconds)
        self.heartbeat_interval = 60  # Send heartbeat every 60 seconds
        self.scan_interval = 300      # Scan every 5 minutes (300 seconds)
        
        # Local storage paths
        self.data_dir = Path.home() / ".cybersec"
        self.agent_id_file = self.data_dir / "agent_id.txt"
        self.api_key_file = self.data_dir / "api_key.txt"
        self.log_file = self.data_dir / "agent.log"
        
        # Scan paths
        self.downloads_folder = Path.home() / "Downloads"
        
        # ClamAV settings
        self.clamav_path = self._find_clamav()
        
        # Load API key from file if not in environment
        if not self.api_key:
            self._load_api_key()
    
    def _load_api_key(self):
        """Load API key from local file if it exists."""
        if self.api_key_file.exists():
            try:
                self.api_key = self.api_key_file.read_text().strip()
            except Exception:
                pass
    
    def save_api_key(self, api_key: str):
        """Save API key to local file."""
        try:
            self.api_key_file.parent.mkdir(parents=True, exist_ok=True)
            self.api_key_file.write_text(api_key)
            self.api_key = api_key
        except Exception as e:
            print(f"⚠️ Could not save API key: {e}")
    
    def _find_clamav(self) -> str:
        """Find ClamAV executable on the system."""
        # Try common paths
        common_paths = [
            "/usr/bin/clamscan",           # Linux
            "/usr/local/bin/clamscan",     # macOS Homebrew
            r"C:\Program Files\ClamAV\clamscan.exe",  # Windows standard
            r"C:\ProgramData\chocolatey\lib\clamav\tools\clamav-1.4.2.win.x64\clamscan.exe",  # Chocolatey install
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Default to just 'clamscan' and hope it's in PATH
        return "clamscan"
    
    def __repr__(self):
        return f"<Config backend={self.backend_url}>"