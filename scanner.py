import re
import base64
import requests
from urllib.parse import urlparse

class URLScanner:
    def __init__(self, vt_api_key=None):
        """
        Initialize the scanner with an optional VirusTotal API key.
        Always store your API keys in environment variables in production!
        """
        self.vt_api_key = vt_api_key
        # Common keywords used in phishing URLs
        self.suspicious_keywords = ['login', 'secure', 'account', 'update', 'banking', 'verify', 'wallet', 'free']
        # Common URL shorteners (often used to hide malicious links)
        self.shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']

    def check_heuristics(self, url):
        """
        Performs a static analysis of the URL structure.
        Returns a dictionary with findings and a base risk score.
        """
        score = 0
        findings = []
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
        except Exception:
            return {"error": "Invalid URL format"}

        # 1. Check if the domain is an IP address (e.g., http://192.168.1.1/login)
        # Phishers often use raw IPs instead of registered domains.
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        if ip_pattern.match(domain):
            score += 30
            findings.append("Uses an IP address instead of a domain name.")

        # 2. Check for URL shorteners
        if any(shortener in domain for shortener in self.shorteners):
            score += 20
            findings.append("Uses a URL shortening service.")

        # 3. Check for suspicious keywords in the domain or path
        found_keywords = [kw for kw in self.suspicious_keywords if kw in domain or kw in path]
        if found_keywords:
            score += (15 * len(found_keywords))
            findings.append(f"Contains suspicious keywords: {', '.join(found_keywords)}.")

        # 4. Check for unusually long URLs (often used to hide the actual domain)
        if len(url) > 75:
            score += 10
            findings.append("URL is unusually long.")

        # 5. Check for multiple subdomains (e.g., login.secure.banking.com)
        if domain.count('.') > 3:
            score += 15
            findings.append("Contains an excessive number of subdomains.")

        # Cap the heuristic score at 100
        score = min(score, 100)

        return {
            "heuristic_score": score,
            "findings": findings
        }

    def check_virustotal(self, url):
        """
        Queries the VirusTotal v3 API for the URL's reputation.
        """
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not provided."}

        # VirusTotal v3 requires the URL to be base64 encoded (URL-safe, no padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "accept": "application/json",
            "x-apikey": self.vt_api_key
        }

        try:
            response = requests.get(endpoint, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                # Calculate an API threat score based on malicious/suspicious flags
                total_engines = sum(stats.values())
                bad_flags = stats['malicious'] + stats['suspicious']
                
                api_score = (bad_flags / total_engines) * 100 if total_engines > 0 else 0
                
                return {
                    "vt_score": round(api_score, 2),
                    "malicious_flags": stats['malicious'],
                    "suspicious_flags": stats['suspicious'],
                    "harmless_flags": stats['harmless']
                }
            elif response.status_code == 404:
                return {"message": "URL not found in VirusTotal database (Unscanned)."}
            else:
                return {"error": f"VirusTotal API Error: {response.status_code}"}
                
        except Exception as e:
            return {"error": str(e)}

    def scan(self, url):
        """
        Combines heuristics and API checks into a final comprehensive report.
        """
        print(f"[*] Scanning URL: {url}")
        
        report = {
            "url": url,
            "heuristics": self.check_heuristics(url),
            "threat_intelligence": {}
        }

        if self.vt_api_key:
            report["threat_intelligence"] = self.check_virustotal(url)
        
        # Determine overall risk level (Custom Logic)
        heuristic_score = report["heuristics"].get("heuristic_score", 0)
        vt_score = report.get("threat_intelligence", {}).get("vt_score", 0)
        
        # VirusTotal carries more weight than heuristics
        final_score = max(heuristic_score * 0.4, vt_score)
        report["final_threat_score"] = round(final_score, 2)

        if final_score > 50:
            report["risk_level"] = "HIGH"
        elif final_score > 20:
            report["risk_level"] = "MEDIUM"
        else:
            report["risk_level"] = "LOW"

        return report

# --- Example Usage ---
if __name__ == "__main__":
    # Replace with your actual VirusTotal API Key
    API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" 
    
    scanner = URLScanner(vt_api_key=API_KEY)
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.55/secure/login.php",
        "https://bit.ly/3xyz789"
    ]
    
    for test_url in test_urls:
        results = scanner.scan(test_url)
        print(f"Risk Level: {results.get('risk_level')} (Score: {results.get('final_threat_score')} / 100)")
        print(f"Findings: {results['heuristics']['findings']}")
        print("-" * 40)