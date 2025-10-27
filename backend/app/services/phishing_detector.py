import requests
import time
import json
import hashlib
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import os
import logging

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.cache = {}
        self.cache_duration = timedelta(hours=24)
        self.rate_limit_calls = 0
        self.rate_limit_window_start = time.time()
        self.max_calls_per_minute = 100
        
        if not self.api_key:
            logger.warning("Google Safe Browsing API key not provided")
    
    def _check_rate_limit(self) -> bool:
        current_time = time.time()
        
        # Reset counter if window expired
        if current_time - self.rate_limit_window_start >= 60:
            self.rate_limit_calls = 0
            self.rate_limit_window_start = current_time
        
        if self.rate_limit_calls >= self.max_calls_per_minute:
            return False
        
        self.rate_limit_calls += 1
        return True
    
    def _get_cache_key(self, url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()
    
    def _is_cache_valid(self, timestamp: datetime) -> bool:
        return datetime.now() - timestamp < self.cache_duration
    
    def _get_from_cache(self, url: str) -> Optional[Dict]:
        cache_key = self._get_cache_key(url)
        if cache_key in self.cache:
            cached_data = self.cache[cache_key]
            if self._is_cache_valid(cached_data['timestamp']):
                logger.info(f"Cache hit for URL: {url}")
                return cached_data['result']
            else:
                del self.cache[cache_key]
        return None
    
    def _store_in_cache(self, url: str, result: Dict) -> None:
        cache_key = self._get_cache_key(url)
        self.cache[cache_key] = {
            'result': result,
            'timestamp': datetime.now()
        }
    
    def _prepare_request_body(self, urls: List[str]) -> Dict:
        threat_entries = [{"url": url} for url in urls]
        
        return {
            "client": {
                "clientId": "cybersec-suite",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries
            }
        }
    
    def _parse_threat_type(self, threat_type: str) -> str:
        threat_mapping = {
            "MALWARE": "malware",
            "SOCIAL_ENGINEERING": "phishing",
            "UNWANTED_SOFTWARE": "unwanted_software",
            "POTENTIALLY_HARMFUL_APPLICATION": "potentially_harmful"
        }
        return threat_mapping.get(threat_type, "unknown_threat")
    
    def check_url(self, url: str) -> Dict:
        """
        Check a single URL against Google Safe Browsing API
        
        Args:
            url (str): URL to check
            
        Returns:
            Dict: Result containing threat information
        """
        try:
            # Check cache first
            cached_result = self._get_from_cache(url)
            if cached_result:
                return cached_result
            
            # Check rate limit
            if not self._check_rate_limit():
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": "Rate limit exceeded. Please try again later."
                }
            
            # Check if API key is available
            if not self.api_key:
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": "API key not configured"
                }
            
            # Prepare request
            request_body = self._prepare_request_body([url])
            params = {"key": self.api_key}
            
            # Make API request
            response = requests.post(
                self.base_url,
                params=params,
                json=request_body,
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            
            # Handle API response
            if response.status_code == 200:
                data = response.json()
                
                # No threats found
                if "matches" not in data:
                    result = {
                        "url": url,
                        "is_safe": True,
                        "threat_type": None,
                        "error": None
                    }
                else:
                    # Threats found
                    match = data["matches"][0]
                    threat_type = self._parse_threat_type(match.get("threatType", ""))
                    
                    result = {
                        "url": url,
                        "is_safe": False,
                        "threat_type": threat_type,
                        "platform_type": match.get("platformType", ""),
                        "threat_entry_type": match.get("threatEntryType", ""),
                        "error": None
                    }
                
                # Cache the result
                self._store_in_cache(url, result)
                return result
                
            elif response.status_code == 400:
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": "Bad request - invalid URL format"
                }
            elif response.status_code == 401:
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": "Unauthorized - invalid API key"
                }
            elif response.status_code == 429:
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": "API quota exceeded"
                }
            else:
                return {
                    "url": url,
                    "is_safe": None,
                    "threat_type": None,
                    "error": f"API error: {response.status_code}"
                }
                
        except requests.exceptions.Timeout:
            return {
                "url": url,
                "is_safe": None,
                "threat_type": None,
                "error": "Request timeout"
            }
        except requests.exceptions.ConnectionError:
            return {
                "url": url,
                "is_safe": None,
                "threat_type": None,
                "error": "Connection error"
            }
        except requests.exceptions.RequestException as e:
            return {
                "url": url,
                "is_safe": None,
                "threat_type": None,
                "error": f"Request error: {str(e)}"
            }
        except Exception as e:
            logger.error(f"Unexpected error checking URL {url}: {str(e)}")
            return {
                "url": url,
                "is_safe": None,
                "threat_type": None,
                "error": "Unexpected error occurred"
            }
    
    def check_multiple_urls(self, urls: List[str]) -> List[Dict]:
        """
        Check multiple URLs against Google Safe Browsing API
        
        Args:
            urls (List[str]): List of URLs to check
            
        Returns:
            List[Dict]: List of results for each URL
        """
        results = []
        for url in urls:
            result = self.check_url(url)
            results.append(result)
        return results
    
    def clear_cache(self) -> None:
        """Clear the cache"""
        self.cache.clear()
        logger.info("Cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        valid_entries = 0
        expired_entries = 0
        
        for cache_data in self.cache.values():
            if self._is_cache_valid(cache_data['timestamp']):
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            "total_entries": len(self.cache),
            "valid_entries": valid_entries,
            "expired_entries": expired_entries
        }

def test_phishing_detector():
    """
    Test function to demonstrate phishing detector functionality
    """
    print("Testing Phishing Detector...")
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Test URLs (including known safe and potentially unsafe examples)
    test_urls = [
        "https://www.google.com",  # Safe URL
        "https://example.com",     # Safe URL
        "http://malware.testing.google.test/testing/malware/",  # Google's test malware URL
        "https://testsafebrowsing.appspot.com/s/malware.html",  # Test malware URL
        "https://testsafebrowsing.appspot.com/s/phishing.html"  # Test phishing URL
    ]
    
    print("\nTesting individual URLs:")
    for url in test_urls:
        print(f"\nChecking: {url}")
        result = detector.check_url(url)
        print(f"Result: {json.dumps(result, indent=2)}")
        time.sleep(1)  # Avoid hitting rate limits
    
    print("\n" + "="*50)
    print("Testing batch URL checking:")
    batch_results = detector.check_multiple_urls(test_urls[:2])
    for result in batch_results:
        print(json.dumps(result, indent=2))
    
    print("\n" + "="*50)
    print("Cache statistics:")
    cache_stats = detector.get_cache_stats()
    print(json.dumps(cache_stats, indent=2))
    
    print("\nTesting complete!")

if __name__ == "__main__":
    test_phishing_detector()