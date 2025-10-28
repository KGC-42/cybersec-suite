"""
CyberSec Suite Agent - Full Version with Phishing & Breach Monitoring
"""

import socket
import platform
import requests
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
import getpass
import sys
import warnings
import re
from bs4 import BeautifulSoup

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
        self.user_email = None
        self.is_running = False
        self.scanner = MalwareScanner(self)
        self.last_breach_check = datetime.now() - timedelta(days=1)
        
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
    
    def report_event(self, source: str, severity: str, title: str, description: str, details: dict = None):
        """Report a security event to the backend."""
        if not self.agent_id:
            return False
        
        try:
            payload = {
                "agent_id": self.agent_id,
                "source": source,
                "severity": severity,
                "title": title,
                "description": description,
                "details": details or {},
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.config.backend_url}/api/v1/events/ingest",
                json=payload,
                headers=self._get_auth_headers(),
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"[✓] Reported {severity.upper()} event: {title}")
                return True
            else:
                print(f"[!] Failed to report event: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"[!] Error reporting event: {e}")
            return False
    
    def check_phishing_urls(self):
        """Scan Downloads folder for HTML files and check URLs for phishing"""
        try:
            downloads_path = Path.home() / "Downloads"
            html_files = list(downloads_path.glob("*.html"))[:10]  # Check last 10 HTML files
            
            if not html_files:
                return
            
            print(f"[*] Checking {len(html_files)} HTML files for phishing URLs...")
            
            for html_file in html_files:
                try:
                    with open(html_file, 'r', encoding='utf-8', errors='ignore') as f:
                        soup = BeautifulSoup(f.read(), 'html.parser')
                        urls = [a.get('href') for a in soup.find_all('a', href=True)]
                        
                        for url in urls[:5]:  # Check first 5 URLs per file
                            if url.startswith('http'):
                                response = requests.post(
                                    f"{self.config.backend_url}/api/v1/phishing/check",
                                    headers=self._get_auth_headers(),
                                    json={"url": url},
                                    timeout=10
                                )
                                
                                if response.status_code == 200:
                                    data = response.json()
                                    if data.get("is_threat"):
                                        self.report_event(
                                            "phishing", 
                                            "high",
                                            f"Phishing URL detected",
                                            f"Malicious URL found in {html_file.name}: {url}",
                                            data
                                        )
                                time.sleep(0.5)  # Rate limit
                
                except Exception as e:
                    print(f"[!] Error checking {html_file.name}: {e}")
        
        except Exception as e:
            print(f"[!] Phishing check error: {e}")
    
    def check_breach_status(self):
        """Check if user email has been in any data breaches"""
        if not self.user_email:
            return
        
        try:
            print(f"[*] Checking {self.user_email} for data breaches...")
            
            response = requests.post(
                f"{self.config.backend_url}/api/v1/breach/check",
                headers=self._get_auth_headers(),
                json={"email": self.user_email},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("breaches"):
                    breach_count = len(data["breaches"])
                    self.report_event(
                        "darkweb",
                        "critical",
                        f"Email found in {breach_count} data breaches",
                        f"Email {self.user_email} has been compromised in {breach_count} breaches",
                        data
                    )
                    print(f"[!] WARNING: {breach_count} breaches found!")
                else:
                    print(f"[✓] No breaches found for {self.user_email}")
        
        except Exception as e:
            print(f"[!] Breach check error: {e}")
    
    def login(self, email: str = None, password: str = None):
        """Login to get access token."""
        print("\n[*] Authenticating with backend...")
        
        # Prompt for credentials if not provided
        if not email:
            email = input("Email: ")
        if not password:
            password = getpass.getpass("Password: ")
        
        self.user_email = email  # Save for breach checking
        
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
    
    def background_tasks(self):
        """Background thread: Heartbeat, phishing checks, breach monitoring."""
        print(f"[*] Background tasks started")
        print(f"   • Heartbeat: Every {self.config.heartbeat_interval}s")
        print(f"   • Phishing checks: Every scan cycle")
        print(f"   • Breach monitoring: Daily")
        
        while self.is_running:
            # Heartbeat
            self.send_heartbeat()
            
            # Check for phishing URLs
            self.check_phishing_urls()
            
            # Check breaches once per day
            if (datetime.now() - self.last_breach_check).days >= 1:
                self.check_breach_status()
                self.last_breach_check = datetime.now()
            
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
        print("[*] CyberSec Suite Agent v1.1 - With Phishing & Breach Detection")
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
        
        # Step 3: Initial breach check
        self.check_breach_status()
        
        # Step 4: Start background threads
        self.is_running = True
        
        background_thread = threading.Thread(target=self.background_tasks, daemon=True)
        scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        
        background_thread.start()
        scan_thread.start()
        
        print("\n[+] Agent started successfully!")
        print(f"   Agent ID: {self.agent_id}")
        print(f"   Monitoring: {self.user_email}")
        print(f"   Background tasks: Every {self.config.heartbeat_interval}s")
        print(f"   Malware scanning: Every {self.config.scan_interval}s")
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
            test_endpoints = ["/health", "/api/health", "/api/v1/health", "", "/ping"]
            
            for endpoint in test_endpoints:
                try:
                    response = requests.get(
                        f"{self.config.backend_url}{endpoint}",
                        timeout=5
                    )
                    
                    if response.status_code in [200, 301, 302]:
                        print(f"[+] Backend is reachable at {endpoint}!")
                        return True
                except:
                    continue
            
            print(f"[!] Backend at {self.config.backend_url} is not responding")
            print("[i] Continuing anyway - backend might still work for API calls")
            return True
        
        except Exception as e:
            print(f"[-] Cannot reach backend: {e}")
            return True


# Main entry point
if __name__ == "__main__":
    agent = CyberSecAgent()
    
    # Test connection
    agent.test_connection()
    
    # Login
    if not agent.login():
        print("\n[-] Login failed. Exiting.")
        exit(1)
    
    # Start agent (runs continuously)
    agent.start()