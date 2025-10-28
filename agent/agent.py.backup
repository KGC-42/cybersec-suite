"""
CyberSec Suite Agent - Full Version with Background Loops
"""

import socket
import platform
import requests
import threading
import time
from pathlib import Path
from datetime import datetime
import getpass
import sys
import warnings

# Suppress the pkg_resources warning
warnings.filterwarnings("ignore", message="pkg_resources is deprecated")

from config import Config
from scanner import MalwareScanner


class CyberSecAgent:
    def __init__(self):
        # Set UTF-8 encoding for Windows console
        if sys.platform.startswith('win'):
            import os
            os.system('chcp 65001 > nul')
            sys.stdout.reconfigure(encoding='utf-8')
            sys.stderr.reconfigure(encoding='utf-8')
        
        self.config = Config()
        self.agent_id = None
        self.access_token = None
        self.is_running = False
        self.scanner = MalwareScanner(self)
        
        # Try to load existing agent ID
        self._load_agent_id()
    
    def _load_agent_id(self):
        """Load agent ID from local file if it exists."""
        if self.config.agent_id_file.exists():
            try:
                self.agent_id = self.config.agent_id_file.read_text().strip()
                print(f"[+] Found existing agent ID: {self.agent_id}")
            except Exception as e:
                print(f"[!] Could not load agent ID: {e}")
    
    def _save_agent_id(self, agent_id: str):
        """Save agent ID to local file."""
        try:
            self.config.agent_id_file.parent.mkdir(parents=True, exist_ok=True)
            self.config.agent_id_file.write_text(agent_id)
            self.agent_id = agent_id
            print(f"[*] Saved agent ID to: {self.config.agent_id_file}")
        except Exception as e:
            print(f"[-] Could not save agent ID: {e}")
    
    def _get_device_info(self):
        """Gather information about this device."""
        return {
            "hostname": socket.gethostname(),
            "os_type": platform.system(),
            "os_version": platform.version(),
            "ip_address": self._get_local_ip(),
        }
    
    def _get_local_ip(self):
        """Get the local IP address of this machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "unknown"
    
    def _get_auth_headers(self):
        """Get headers with authentication."""
        if self.access_token:
            return {
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            }
        else:
            return {"Content-Type": "application/json"}
    
    def login(self, email: str = None, password: str = None):
        """Login to get access token."""
        print("\n[*] Authenticating with backend...")
        
        # Prompt for credentials if not provided
        if not email:
            email = input("Email: ")
        if not password:
            password = getpass.getpass("Password: ")
        
        try:
            response = requests.post(
                f"{self.config.backend_url}/auth/login",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.access_token = data.get("access_token")
                
                if self.access_token:
                    print("[+] Login successful!")
                    return True
                else:
                    print("[!] Login succeeded but no token returned")
                    return False
            else:
                print(f"[-] Login failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        
        except Exception as e:
            print(f"[-] Login error: {e}")
            return False
    
    def register(self):
        """Register this agent with the backend."""
        if self.agent_id:
            print("[i] Agent already registered, skipping...")
            return True
        
        print("\n[*] Registering agent with backend...")
        print(f"   Backend URL: {self.config.backend_url}")
        
        device_info = self._get_device_info()
        
        print(f"   Hostname: {device_info['hostname']}")
        print(f"   OS: {device_info['os_type']}")
        print(f"   IP: {device_info['ip_address']}")
        
        payload = {
            "hostname": device_info["hostname"],
            "os_type": device_info["os_type"],
            "os_version": device_info["os_version"],
            "ip_address": device_info["ip_address"],
            "platform": device_info["os_type"].lower(),
            "arch": platform.machine(),
            "agent_version": "1.0.0",
        }
        
        try:
            response = requests.post(
                f"{self.config.backend_url}/api/v1/agents/register",
                json=payload,
                headers=self._get_auth_headers(),
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                data = response.json()
                agent_id = data.get("id") or data.get("agent_id")
                
                if agent_id:
                    self._save_agent_id(str(agent_id))
                    print(f"\n[+] Registration successful!")
                    print(f"   Agent ID: {agent_id}")
                    return True
                else:
                    print(f"[!] Registration succeeded but no agent ID returned")
                    return False
            else:
                print(f"\n[-] Registration failed!")
                print(f"   Status Code: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        
        except requests.exceptions.ConnectionError:
            print(f"\n[-] Could not connect to backend!")
            return False
        
        except Exception as e:
            print(f"\n[-] Unexpected error: {e}")
            return False
    
    def send_heartbeat(self):
        """Send a heartbeat to show this agent is alive."""
        if not self.agent_id:
            return False
        
        try:
            response = requests.post(
                f"{self.config.backend_url}/api/v1/agents/{self.agent_id}/heartbeat",
                json={"timestamp": datetime.now().isoformat()},
                headers=self._get_auth_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                current_time = datetime.now().strftime("%H:%M:%S")
                print(f"<3 Heartbeat sent at {current_time}")
                return True
            else:
                return False
        
        except Exception:
            return False
    
    def heartbeat_loop(self):
        """Background thread: Send heartbeat every 60 seconds."""
        print(f"<3 Heartbeat loop started (every {self.config.heartbeat_interval}s)")
        
        while self.is_running:
            self.send_heartbeat()
            time.sleep(self.config.heartbeat_interval)
    
    def scan_loop(self):
        """Background thread: Scan Downloads every 5 minutes."""
        print(f"[*] Scan loop started (every {self.config.scan_interval}s)")
        
        # Wait 10 seconds before first scan
        time.sleep(10)
        
        while self.is_running:
            print(f"\n{'='*60}")
            print(f"[*] Starting scan at {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}")
            
            self.scanner.scan_downloads_folder()
            
            print(f"[*] Next scan in {self.config.scan_interval} seconds\n")
            time.sleep(self.config.scan_interval)
    
    def start(self):
        """Start the agent with background loops."""
        print("\n" + "="*60)
        print("[*] CyberSec Suite Agent v1.0")
        print("="*60 + "\n")
        
        # Step 1: Register
        if not self.register():
            print("\n[-] Registration failed. Exiting.")
            return
        
        # Step 2: Check ClamAV
        print("\n[*] Verifying ClamAV installation...")
        if not self.scanner.verify_clamav():
            print("\n[!] ClamAV not found. Install it first:")
            print("   • Ubuntu/Debian: sudo apt-get install clamav")
            print("   • macOS: brew install clamav")
            print("   • Windows: https://www.clamav.net/downloads")
            print("\n[!] Agent will run without scanning until ClamAV is installed.")
        
        # Step 3: Start background threads
        self.is_running = True
        
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        
        heartbeat_thread.start()
        scan_thread.start()
        
        print("\n[+] Agent started successfully!")
        print(f"   Agent ID: {self.agent_id}")
        print(f"   Heartbeat: Every {self.config.heartbeat_interval}s")
        print(f"   Scanning: Every {self.config.scan_interval}s")
        print("\nPress Ctrl+C to stop the agent.\n")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n[!] Stopping agent...")
            self.is_running = False
            time.sleep(2)
            print("[+] Agent stopped.")
    
    def test_connection(self):
        """Test the connection to the backend."""
        print("\n[*] Testing backend connection...")
        
        try:
            response = requests.get(
                f"{self.config.backend_url}/health",
                timeout=5
            )
            
            if response.status_code == 200:
                print("[+] Backend is reachable!")
                return True
            else:
                print(f"[!] Backend returned status: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"[-] Cannot reach backend: {e}")
            return False


# Main entry point
if __name__ == "__main__":
    agent = CyberSecAgent()
    
    # Test connection
    if not agent.test_connection():
        print("\n[-] Cannot reach backend. Check your internet connection.")
        exit(1)
    
    # Login
    if not agent.login():
        print("\n[-] Login failed. Exiting.")
        exit(1)
    
    # Start agent (runs continuously)
    agent.start()