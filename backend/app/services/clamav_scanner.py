import subprocess
from typing import Dict
from datetime import datetime

class ClamAVScanner:
    """Simple ClamAV file scanner"""
    
    def scan_file(self, file_path: str) -> Dict:
        """Scan a file with ClamAV"""
        try:
            result = subprocess.run(
                ["docker", "exec", "cybersec_clamav", "clamdscan", "--no-summary", file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output = result.stdout
            infected = "FOUND" in output
            
            if infected:
                for line in output.split("\n"):
                    if "FOUND" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            virus_name = parts[1].replace("FOUND", "").strip()
                            return {
                                "infected": True,
                                "virus_name": virus_name,
                                "file_path": file_path,
                                "scanned_at": datetime.utcnow().isoformat()
                            }
            
            return {
                "infected": False,
                "file_path": file_path,
                "scanned_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {"error": str(e), "file_path": file_path}
    
    def test_eicar(self) -> Dict:
        """Test with EICAR test file"""
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        
        try:
            # Create EICAR file in container
            subprocess.run(
                ["docker", "exec", "cybersec_clamav", "sh", "-c", 
                 f"echo '{eicar}' > /tmp/eicar.com"],
                capture_output=True,
                timeout=5
            )
            
            # Scan it
            return self.scan_file("/tmp/eicar.com")
            
        except Exception as e:
            return {"error": str(e)}