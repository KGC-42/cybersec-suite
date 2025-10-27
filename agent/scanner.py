"""
ClamAV Scanner - OPTIMIZED with clamd daemon
Uses persistent daemon connection instead of subprocess calls for 10-100x faster scanning
"""

import subprocess
import os
from pathlib import Path
from datetime import datetime
import requests
import logging

logger = logging.getLogger(__name__)

# Try to import clamd (Python client for ClamAV daemon)
try:
    import clamd
    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False
    logger.warning("clamd package not installed")


class MalwareScanner:
    def __init__(self, agent):
        self.agent = agent
        self.config = agent.config
        self.use_daemon = False
        self.clamd_client = None
        
        # Try to connect to daemon first
        if CLAMD_AVAILABLE:
            self._init_daemon()
        
        # Fallback to subprocess if daemon unavailable
        if not self.clamd_client:
            print("⚠️ Using subprocess mode (slow) - daemon not available")
    
    def _init_daemon(self):
        """Initialize connection to clamd daemon"""
        try:
            # Try TCP socket (Windows)
            self.clamd_client = clamd.ClamdNetworkSocket(host='localhost', port=3310)
            self.clamd_client.ping()
            self.use_daemon = True
            print("✅ Connected to clamd daemon (FAST MODE)")
            return True
        except Exception as e:
            logger.debug(f"Could not connect to clamd: {e}")
            return False
    
    def verify_clamav(self):
        """Check if ClamAV is installed."""
        if self.use_daemon:
            try:
                self.clamd_client.ping()
                print("✅ ClamAV daemon is running")
                return True
            except:
                print("⚠️ ClamAV daemon not responding")
                return False
        
        # Fallback: check clamscan
        try:
            result = subprocess.run(
                [self.config.clamav_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                print(f"✅ ClamAV found: {version}")
                return True
            return False
        
        except Exception as e:
            print(f"❌ Error checking ClamAV: {e}")
            return False
    
    def scan_file(self, file_path):
        """Scan a single file - uses daemon if available, subprocess as fallback"""
        # Try daemon first (FAST)
        if self.use_daemon and self.clamd_client:
            try:
                result = self.clamd_client.scan(str(file_path))
                
                if result is None:
                    # Clean file
                    return {"infected": False, "file_path": str(file_path)}
                
                # Infected file
                for file, status in result.items():
                    if status[0] == "FOUND":
                        threat_name = status[1]
                        return {
                            "infected": True,
                            "threat_name": threat_name,
                            "file_path": str(file_path)
                        }
                
                return {"infected": False, "file_path": str(file_path)}
                
            except Exception as e:
                logger.error(f"Daemon scan failed: {e}")
                # Fall through to subprocess
        
        # Fallback: subprocess (SLOW)
        try:
            print(f"   📄 Scanning: {file_path.name}")
            
            result = subprocess.run(
                [self.config.clamav_path, str(file_path)],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 1 and "FOUND" in result.stdout:
                output = result.stdout.strip()
                parts = output.split(":")
                threat_name = parts[1].strip().replace("FOUND", "").strip() if len(parts) >= 2 else "Unknown"
                
                return {
                    "infected": True,
                    "threat_name": threat_name,
                    "file_path": str(file_path)
                }
            
            return {"infected": False, "file_path": str(file_path)}
        
        except Exception as e:
            print(f"❌ Scan error: {e}")
            return {"infected": False, "file_path": str(file_path), "error": str(e)}
    
    def scan_downloads_folder(self):
        """Scan all files in Downloads folder"""
        if not self.config.downloads_folder.exists():
            print(f"⚠️ Downloads folder not found")
            return
        
        print(f"🔍 Scanning: {self.config.downloads_folder}")
        
        files_scanned = 0
        threats_found = 0
        
        try:
            all_files = [f for f in self.config.downloads_folder.iterdir() if f.is_file()]
            print(f"📊 Found {len(all_files)} files to scan")
            
            if self.use_daemon:
                print("⚡ Using FAST daemon mode")
            else:
                print("🐌 Using SLOW subprocess mode")
            
            for file_path in all_files:
                files_scanned += 1
                
                if self.use_daemon:
                    # Show progress every 10 files in daemon mode
                    if files_scanned % 10 == 0:
                        print(f"   Progress: {files_scanned}/{len(all_files)} files...")
                else:
                    # Show every file in subprocess mode
                    print(f"   📄 {files_scanned}/{len(all_files)}: {file_path.name}")
                
                result = self.scan_file(file_path)
                
                if result.get("infected"):
                    threats_found += 1
                    print(f"🚨 THREAT DETECTED: {result['threat_name']}")
                    print(f"   File: {result['file_path']}")
                    self.report_threat(result)
            
            print(f"✅ Scan complete: {files_scanned} files, {threats_found} threats")
        
        except Exception as e:
            print(f"❌ Scan error: {e}")
    
    def report_threat(self, threat_data):
        """Report detected threat to backend"""
        if not self.agent.agent_id:
            print("⚠️ Cannot report threat: Agent not registered")
            return
        
        payload = {
            "agent_id": self.agent.agent_id,
            "source": "clamav",
            "event_type": "malware_detected",
            "severity": "critical",
            "title": f"Malware Detected: {threat_data.get('threat_name', 'Unknown')}",
            "description": f"ClamAV detected malware in {Path(threat_data.get('file_path')).name}",
            "details": {
                "file_path": threat_data.get("file_path"),
                "threat_name": threat_data.get("threat_name"),
                "scan_time": datetime.utcnow().isoformat()
            }
        }
        
        try:
            response = requests.post(
                f"{self.config.backend_url}/api/v1/events/ingest",
                json=payload,
                headers=self.agent._get_auth_headers(),
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                print(f"✅ Threat reported to backend")
            else:
                print(f"⚠️ Failed to report threat: {response.status_code}")
        
        except Exception as e:
            print(f"❌ Error reporting threat: {e}")
    
    def test_with_eicar(self):
        """Test scanner with EICAR test virus"""
        print("\n🧪 Testing with EICAR test file...")
        
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        test_file = self.config.downloads_folder / "eicar_test.txt"
        
        try:
            test_file.write_text(eicar)
            result = self.scan_file(test_file)
            
            if result.get("infected"):
                print(f"✅ Scanner working! Detected: {result['threat_name']}")
                self.report_threat(result)
            else:
                print("⚠️ Scanner didn't detect EICAR")
            
            test_file.unlink()
            print("🧹 Cleaned up test file")
        
        except Exception as e:
            print(f"❌ Test failed: {e}")