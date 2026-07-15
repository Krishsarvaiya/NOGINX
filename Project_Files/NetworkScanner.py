"""
Network Scanner - Automated network scanning with threat detection integration
Scans for active hosts and open ports, saves results to CSV for threat analysis
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import csv
import os
from datetime import datetime
import json


class NetworkScanner:
    def __init__(self, auto_scan=False, scan_interval=300, output_dir='.'):
        """
        Initialize network scanner
        
        Args:
            auto_scan: Enable automatic scanning
            scan_interval: Seconds between auto-scans (default 5 min)
            output_dir: Directory to save CSV files
        """
        self.timeout = 1
        self.max_workers = 50
        self.auto_scan = auto_scan
        self.scan_interval = scan_interval
        self.output_dir = output_dir
        self.scanning = False
        self.last_scan_time = None
        
        # Create output directory if needed
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def start_auto_scan(self, targets):
        """Start automatic scanning of targets at regular intervals"""
        self.scanning = True
        print(f"[*] Starting auto-scan (interval: {self.scan_interval}s)")
        
        scan_thread = threading.Thread(
            target=self._auto_scan_loop,
            args=(targets,),
            daemon=True
        )
        scan_thread.start()
        return scan_thread
    
    def _auto_scan_loop(self, targets):
        """Background thread for continuous scanning"""
        while self.scanning:
            try:
                for target in targets:
                    print(f"\n[*] Auto-scan running at {datetime.now()}")
                    results = self.scan(target)
                    self.save_to_csv(results)
                    self.save_to_json(results)
                
                self.last_scan_time = datetime.now()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"[!] Auto-scan error: {e}")
                time.sleep(self.scan_interval)
    
    def stop_auto_scan(self):
        """Stop automatic scanning"""
        self.scanning = False
        print("[*] Auto-scan stopped")
    
    def save_to_csv(self, results):
        """Save scan results to CSV file"""
        timestamp = datetime.now().strftime("%Y%m%d")
        csv_file = os.path.join(self.output_dir, f"scan_results_{timestamp}.csv")
        
        try:
            file_exists = os.path.exists(csv_file)
            
            # Prepare rows based on result type
            rows = []
            
            if 'active_hosts' in results:
                # Network scan results
                for host_info in results['active_hosts']:
                    for port_info in host_info.get('open_ports', []):
                        rows.append({
                            'timestamp': datetime.now().isoformat(),
                            'scan_type': 'network',
                            'host': host_info['host'],
                            'port': port_info['port'],
                            'service': port_info['service'],
                            'status': 'open'
                        })
            else:
                # Single host scan results
                for port_info in results.get('open_ports', []):
                    rows.append({
                        'timestamp': datetime.now().isoformat(),
                        'scan_type': 'host',
                        'host': results['host'],
                        'port': port_info['port'],
                        'service': port_info['service'],
                        'status': 'open'
                    })
            
            # Write to CSV
            if rows:
                with open(csv_file, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                    if not file_exists:
                        writer.writeheader()
                    writer.writerows(rows)
                
                print(f"[+] Saved {len(rows)} scan results to: {csv_file}")
            
            return csv_file
        except Exception as e:
            print(f"[!] Error saving to CSV: {e}")
            return None
    
    def save_to_json(self, results):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = os.path.join(self.output_dir, f"scan_results_{timestamp}.json")
        
        try:
            results['timestamp'] = datetime.now().isoformat()
            
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"[+] Saved detailed results to: {json_file}")
            return json_file
        except Exception as e:
            print(f"[!] Error saving to JSON: {e}")
            return None
    
    def scan(self, target):
        """Scan a network or host"""
        print(f"\n[*] Scanning: {target}")
        
        # Check if single host or network
        if '/' in target:
            return self.scan_network(target)
        else:
            return self.scan_host(target)
    
    def scan_host(self, host, ports=None):
        """Scan a single host for open ports"""
        if ports is None:
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    3306, 3389, 5432, 5900, 8080, 8443]
        
        results = {
            'host': host,
            'open_ports': [],
            'scan_time': time.time()
        }
        
        print(f"[*] Scanning {host}...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_port, host, port): port 
                      for port in ports}
            
            for future in futures:
                port = futures[future]
                if future.result():
                    service = self._get_service(port)
                    results['open_ports'].append({
                        'port': port,
                        'service': service
                    })
                    print(f"  [+] Port {port} ({service}) - OPEN")
        
        return results
    
    def scan_network(self, network):
        """Scan a network range for active hosts"""
        # Simple implementation - scan 192.168.1.0/24 as example
        base_ip = '.'.join(network.split('.')[:-1])
        
        results = {
            'network': network,
            'active_hosts': [],
            'scan_time': time.time()
        }
        
        print(f"[*] Scanning network {network}...")
        
        active_hosts = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_host, f"{base_ip}.{i}"): i 
                      for i in range(1, 255)}
            
            for future in futures:
                host = future.result()
                if host:
                    active_hosts.append(host)
                    print(f"  [+] Active host: {host}")
        
        # Scan each active host for open ports
        for host in active_hosts:
            host_info = self.scan_host(host, ports=[22, 80, 443, 3389, 8080])
            results['active_hosts'].append(host_info)
        
        return results
    
    def _check_port(self, host, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _ping_host(self, host):
        """Check if host is active (using port 80 as a simple check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, 80))
            sock.close()
            if result == 0:
                return host
            # Try port 443 as well
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, 443))
            sock.close()
            if result == 0:
                return host
        except:
            pass
        return None
    
    def _get_service(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port-{port}')


if __name__ == '__main__':
    # Example 1: Manual scan with CSV export
    print("=" * 80)
    print("EXAMPLE 1: Manual Single Host Scan")
    print("=" * 80)
    scanner = NetworkScanner(output_dir='./scan_results')
    results = scanner.scan_host('127.0.0.1')
    print(f"Results: {results}")
    scanner.save_to_csv(results)
    scanner.save_to_json(results)
    
    # Example 2: Automatic scanning with CSV export
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Automatic Network Scanning (60-second interval)")
    print("=" * 80)
    print("[*] This will scan every 60 seconds and save results to CSV")
    print("[*] Press Ctrl+C to stop\n")
    
    scanner_auto = NetworkScanner(
        auto_scan=True,
        scan_interval=60,
        output_dir='./scan_results'
    )
    
    # Targets to scan (modify as needed)
    targets = [
        '127.0.0.1',      # localhost
        # '192.168.1.0/24', # uncomment to scan local network
    ]
    
    # Start auto-scanning
    scan_thread = scanner_auto.start_auto_scan(targets)
    
    try:
        # Keep running until interrupted
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping scanner...")
        scanner_auto.stop_auto_scan()
        print("[+] Scan results saved to ./scan_results/ directory")
