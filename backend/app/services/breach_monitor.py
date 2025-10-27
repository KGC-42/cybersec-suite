import requests
import hashlib
import time
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json
import os

class BreachMonitor:
    def __init__(self):
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.password_url = "https://api.pwnedpasswords.com/range"
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        self.last_request_time = 0
        self.request_delay = 1.5  # seconds
        
    def _rate_limit(self):
        """Ensure rate limiting between API requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay:
            time.sleep(self.request_delay - time_since_last)
        self.last_request_time = time.time()
    
    def _is_cache_valid(self, email: str) -> bool:
        """Check if cached result is still valid"""
        if email not in self.cache:
            return False
        cache_time = self.cache[email].get('timestamp')
        if not cache_time:
            return False
        return datetime.now() - cache_time < self.cache_duration
    
    def _get_cached_result(self, email: str) -> Optional[List[Dict]]:
        """Get cached result if valid"""
        if self._is_cache_valid(email):
            return self.cache[email]['data']
        return None
    
    def _cache_result(self, email: str, data: List[Dict]):
        """Cache the API result"""
        self.cache[email] = {
            'data': data,
            'timestamp': datetime.now()
        }
    
    def check_email(self, email: str) -> Dict:
        """
        Check if email appears in data breaches using Have I Been Pwned API
        
        Args:
            email: Email address to check
            
        Returns:
            Dict containing breach information or error details
        """
        try:
            # Check cache first
            cached_result = self._get_cached_result(email)
            if cached_result is not None:
                return {
                    'success': True,
                    'email': email,
                    'breaches': cached_result,
                    'cached': True
                }
            
            # Rate limiting
            self._rate_limit()
            
            # Make API request
            url = f"{self.base_url}/breachedaccount/{email}"
            headers = {
                'User-Agent': 'CyberSec-Suite-Monitor',
                'hibp-api-key': os.getenv('HIBP_API_KEY', '')  # API key required for v3
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                breaches_data = response.json()
                breaches = []
                
                for breach in breaches_data:
                    breach_info = {
                        'name': breach.get('Name', 'Unknown'),
                        'date': breach.get('BreachDate', 'Unknown'),
                        'description': breach.get('Description', 'No description available'),
                        'domain': breach.get('Domain', 'Unknown'),
                        'data_classes': breach.get('DataClasses', []),
                        'verified': breach.get('IsVerified', False),
                        'fabricated': breach.get('IsFabricated', False),
                        'sensitive': breach.get('IsSensitive', False)
                    }
                    breaches.append(breach_info)
                
                # Cache the result
                self._cache_result(email, breaches)
                
                return {
                    'success': True,
                    'email': email,
                    'breaches': breaches,
                    'cached': False
                }
                
            elif response.status_code == 404:
                # No breaches found - cache empty result
                self._cache_result(email, [])
                return {
                    'success': True,
                    'email': email,
                    'breaches': [],
                    'cached': False
                }
                
            elif response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded. Please try again later.',
                    'status_code': 429
                }
                
            elif response.status_code == 401:
                return {
                    'success': False,
                    'error': 'API key required or invalid. Please check your Have I Been Pwned API key.',
                    'status_code': 401
                }
                
            else:
                return {
                    'success': False,
                    'error': f'API request failed with status code: {response.status_code}',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout. Please try again later.'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error. Please check your internet connection.'
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
    
    def check_password(self, password: str) -> Dict:
        """
        Check if password has been compromised using k-anonymity
        
        Args:
            password: Password to check
            
        Returns:
            Dict containing compromise information
        """
        try:
            # Hash the password with SHA-1
            sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Get first 5 characters for k-anonymity
            prefix = sha1_password[:5]
            suffix = sha1_password[5:]
            
            # Rate limiting
            self._rate_limit()
            
            # Make API request
            url = f"{self.password_url}/{prefix}"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                # Parse response to find matching suffix
                lines = response.text.split('\n')
                for line in lines:
                    if ':' in line:
                        hash_suffix, count = line.strip().split(':')
                        if hash_suffix == suffix:
                            return {
                                'success': True,
                                'compromised': True,
                                'count': int(count),
                                'message': f'Password found in {count} breaches'
                            }
                
                # Password not found in breaches
                return {
                    'success': True,
                    'compromised': False,
                    'count': 0,
                    'message': 'Password not found in known breaches'
                }
                
            else:
                return {
                    'success': False,
                    'error': f'API request failed with status code: {response.status_code}',
                    'status_code': response.status_code
                }
                
        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': 'Request timeout. Please try again later.'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Connection error. Please check your internet connection.'
            }
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }

def test_breach_monitor():
    """Test function to demonstrate breach monitoring functionality"""
    monitor = BreachMonitor()
    
    # Test email check
    print("Testing Breach Monitor...")
    print("-" * 50)
    
    test_email = "test@example.com"
    print(f"Checking email: {test_email}")
    
    email_result = monitor.check_email(test_email)
    if email_result['success']:
        breach_count = len(email_result['breaches'])
        print(f"Found {breach_count} breaches for {test_email}")
        
        if breach_count > 0:
            print("\nBreach details:")
            for breach in email_result['breaches'][:3]:  # Show first 3
                print(f"- {breach['name']} ({breach['date']})")
                print(f"  Description: {breach['description'][:100]}...")
    else:
        print(f"Error checking email: {email_result['error']}")
    
    print("\n" + "-" * 50)
    
    # Test password check
    test_password = "password123"
    print(f"Checking password: {test_password}")
    
    password_result = monitor.check_password(test_password)
    if password_result['success']:
        if password_result['compromised']:
            print(f"Password compromised! Found in {password_result['count']} breaches")
        else:
            print("Password not found in known breaches")
    else:
        print(f"Error checking password: {password_result['error']}")

if __name__ == "__main__":
    test_breach_monitor()