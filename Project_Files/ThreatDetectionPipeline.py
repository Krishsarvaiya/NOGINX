"""
Threat Detection Pipeline
Integrates NetworkScanner with ML-based threat analysis
Combines network scanning + log analysis + threat detection
"""

import pandas as pd
import csv
from datetime import datetime
from pathlib import Path
import json


class ThreatDetectionPipeline:
    """
    Combines network scanning with threat detection
    
    Workflow:
    1. NetworkScanner collects active hosts and open ports (scan_results.csv)
    2. Pipeline enriches with threat classification
    3. Correlates with log analysis (log_analysis.ipynb)
    4. Generates unified threat report
    """
    
    def __init__(self, scan_dir='./scan_results', output_dir='./threat_reports'):
        """Initialize threat detection pipeline"""
        self.scan_dir = Path(scan_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Threat indicators based on port/service
        self.port_risk_scores = {
            21: {'service': 'FTP', 'risk': 0.6, 'category': 'legacy'},
            22: {'service': 'SSH', 'risk': 0.4, 'category': 'remote_access'},
            23: {'service': 'Telnet', 'risk': 0.8, 'category': 'legacy_insecure'},
            25: {'service': 'SMTP', 'risk': 0.3, 'category': 'mail'},
            53: {'service': 'DNS', 'risk': 0.2, 'category': 'dns'},
            80: {'service': 'HTTP', 'risk': 0.3, 'category': 'web'},
            110: {'service': 'POP3', 'risk': 0.4, 'category': 'mail'},
            143: {'service': 'IMAP', 'risk': 0.4, 'category': 'mail'},
            443: {'service': 'HTTPS', 'risk': 0.1, 'category': 'web_secure'},
            445: {'service': 'SMB', 'risk': 0.7, 'category': 'fileshare'},
            3306: {'service': 'MySQL', 'risk': 0.5, 'category': 'database'},
            3389: {'service': 'RDP', 'risk': 0.7, 'category': 'remote_access'},
            5432: {'service': 'PostgreSQL', 'risk': 0.5, 'category': 'database'},
            5900: {'service': 'VNC', 'risk': 0.6, 'category': 'remote_access'},
            8080: {'service': 'HTTP-Alt', 'risk': 0.3, 'category': 'web_alt'},
            8443: {'service': 'HTTPS-Alt', 'risk': 0.2, 'category': 'web_secure_alt'},
        }
    
    def process_scan_results(self, scan_csv_file):
        """
        Process network scan results and add threat classification
        
        Args:
            scan_csv_file: Path to scan_results CSV from NetworkScanner
        
        Returns:
            DataFrame with threat analysis
        """
        print(f"[*] Processing scan results: {scan_csv_file}")
        
        try:
            # Load scan results
            df = pd.read_csv(scan_csv_file)
            
            # Add threat scoring
            df['port_risk'] = df['port'].apply(
                lambda p: self.port_risk_scores.get(p, {}).get('risk', 0.3)
            )
            df['risk_category'] = df['port'].apply(
                lambda p: self.port_risk_scores.get(p, {}).get('category', 'unknown')
            )
            
            # Add threat level classification
            df['threat_level'] = df['port_risk'].apply(self._classify_threat_level)
            
            # Add timestamp if not present
            if 'timestamp' not in df.columns:
                df['timestamp'] = datetime.now().isoformat()
            
            print(f"[+] Processed {len(df)} scan records")
            print(f"[+] Risk distribution:")
            print(df['threat_level'].value_counts().to_string())
            
            return df
        except Exception as e:
            print(f"[!] Error processing scan results: {e}")
            return None
    
    def _classify_threat_level(self, risk_score):
        """Classify threat level from risk score (0-1)"""
        if risk_score >= 0.7:
            return 'HIGH'
        elif risk_score >= 0.5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def correlate_with_logs(self, scan_df, log_csv):
        """
        Correlate network scan results with log file events
        
        Args:
            scan_df: DataFrame from process_scan_results
            log_csv: Path to weblog.csv
        
        Returns:
            Correlated threat analysis DataFrame
        """
        print(f"\n[*] Correlating scan results with log file: {log_csv}")
        
        try:
            # Import classifier dynamically
            from core.detection.classifier import classify_threat_type
            
            # Load CSV format data
            log_df = pd.read_csv(log_csv, on_bad_lines='skip')
            log_df.columns = [str(c).strip() for c in log_df.columns]
            if 'Staus' in log_df.columns and 'Status' not in log_df.columns:
                log_df.rename(columns={'Staus': 'Status'}, inplace=True)
                
            print(f"[+] Loaded {len(log_df)} log records")
            
            # Merge on service/port correlation
            correlation_df = pd.DataFrame()
            
            # Group logs by IP to get counts
            ip_counts = log_df['IP'].value_counts().to_dict()
            
            for idx, scan_row in scan_df.iterrows():
                host = scan_row['host']
                port = scan_row['port']
                service = scan_row['service']
                
                # Find matching logs where the attacker IP matches the scanned host IP
                matching_logs = log_df[log_df['IP'] == host]
                
                if len(matching_logs) > 0:
                    # Let's take up to 20 representative logs to avoid ballooning the correlation df
                    for _, log_row in matching_logs.head(20).iterrows():
                        # Classify threat
                        row_dict = log_row.to_dict()
                        threat_type, confidence = classify_threat_type(row_dict)
                        
                        # Map log confidence/threat_type to a severity label
                        if confidence > 0.8:
                            severity = 'high'
                        elif confidence > 0.5:
                            severity = 'medium'
                        else:
                            severity = 'low'
                            
                        corr_row = {
                            'host': host,
                            'port': port,
                            'service': service,
                            'threat_level': scan_row['threat_level'],
                            'port_risk': scan_row['port_risk'],
                            'attack_type': threat_type,
                            'source_ip': host,
                            'event_count': ip_counts.get(host, len(matching_logs)),
                            'severity': severity,
                            'timestamp': log_row.get('Time', 'unknown')
                        }
                        correlation_df = pd.concat(
                            [correlation_df, pd.DataFrame([corr_row])],
                            ignore_index=True
                        )
            
            print(f"[+] Found {len(correlation_df)} correlated events")
            return correlation_df
        
        except Exception as e:
            print(f"[!] Error correlating data: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def generate_unified_report(self, scan_df, correlation_df=None):
        """
        Generate comprehensive threat report combining scanner + logs + ML analysis
        
        Args:
            scan_df: Scan results DataFrame
            correlation_df: Correlated events DataFrame (optional)
        
        Returns:
            Report file path
        """
        print("\n[*] Generating unified threat report...")
        
        report_file = self.output_dir / f"unified_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 100 + "\n")
                f.write("UNIFIED THREAT DETECTION REPORT\n")
                f.write("Combining Network Scanning + Log Analysis + ML Threat Detection\n")
                f.write("=" * 100 + "\n\n")
                
                # Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 100 + "\n")
                f.write(f"Report Generated: {datetime.now().isoformat()}\n")
                f.write(f"Total Scanned Hosts/Ports: {len(scan_df)}\n")
                
                if correlation_df is not None:
                    f.write(f"Correlated Events: {len(correlation_df)}\n")
                
                # Threat distribution
                threat_dist = scan_df['threat_level'].value_counts()
                f.write(f"\nThreat Level Distribution:\n")
                for level, count in threat_dist.items():
                    pct = count / len(scan_df) * 100
                    f.write(f"  {level}: {count} ({pct:.1f}%)\n")
                
                # High-risk ports
                f.write("\n" + "-" * 100 + "\n")
                f.write("HIGH-RISK PORTS DETECTED\n")
                f.write("-" * 100 + "\n")
                high_risk = scan_df[scan_df['threat_level'] == 'HIGH'].sort_values('port_risk', ascending=False)
                if len(high_risk) > 0:
                    for _, row in high_risk.iterrows():
                        f.write(f"\nHost: {row['host']}\n")
                        f.write(f"  Port: {row['port']} ({row['service']})\n")
                        f.write(f"  Risk Score: {row['port_risk']:.2f}\n")
                        f.write(f"  Category: {row['risk_category']}\n")
                
                # Correlated attack patterns
                if correlation_df is not None and len(correlation_df) > 0:
                    f.write("\n" + "-" * 100 + "\n")
                    f.write("CORRELATED ATTACK PATTERNS\n")
                    f.write("-" * 100 + "\n")
                    
                    attack_patterns = correlation_df.groupby('attack_type').size()
                    for attack_type, count in attack_patterns.items():
                        f.write(f"\n{attack_type}: {count} events\n")
                        
                        # Show details
                        pattern_data = correlation_df[correlation_df['attack_type'] == attack_type]
                        for _, row in pattern_data.head(3).iterrows():
                            f.write(f"  - IP: {row['source_ip']}, Service: {row['service']}, Severity: {row['severity']}\n")
                
                # Recommendations
                f.write("\n" + "-" * 100 + "\n")
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 100 + "\n")
                
                high_risk_count = len(scan_df[scan_df['threat_level'] == 'HIGH'])
                if high_risk_count > 0:
                    f.write(f"\n[CRITICAL] {high_risk_count} high-risk services detected:\n")
                    f.write("  • Disable unnecessary services\n")
                    f.write("  • Implement firewall rules\n")
                    f.write("  • Monitor for exploitation attempts\n")
                
                if correlation_df is not None and 'brute_force' in str(correlation_df.get('attack_type')).lower():
                    f.write(f"\n[WARNING] Brute force attacks detected:\n")
                    f.write("  • Enable account lockout policies\n")
                    f.write("  • Implement multi-factor authentication\n")
                    f.write("  • Use SSH keys instead of passwords\n")
                
                f.write("\n" + "=" * 100 + "\n")
            
            print(f"[+] Report saved to: {report_file}")
            return report_file
        
        except Exception as e:
            print(f"[!] Error generating report: {e}")
            return None
    
    def export_to_csv(self, df, prefix='threat_analysis'):
        """Export analysis results to CSV"""
        csv_file = self.output_dir / f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        try:
            df.to_csv(csv_file, index=False)
            print(f"[+] Exported to: {csv_file}")
            return csv_file
        except Exception as e:
            print(f"[!] Error exporting to CSV: {e}")
            return None


def main():
    """Demo: Integrate NetworkScanner with threat detection"""
    
    print("=" * 100)
    print("THREAT DETECTION PIPELINE - NetworkScanner + Log Analysis Integration")
    print("=" * 100)
    
    pipeline = ThreatDetectionPipeline(
        scan_dir='./scan_results',
        output_dir='./threat_reports'
    )
    
    # Check if we have scan results
    scan_files = list(Path('./scan_results').glob('scan_results_*.csv'))
    
    if scan_files:
        # Process latest scan file
        latest_scan = sorted(scan_files)[-1]
        print(f"\n[*] Using scan file: {latest_scan}")
        
        scan_df = pipeline.process_scan_results(str(latest_scan))
        
        if scan_df is not None:
            # Correlate with logs if available
            log_file = Path('./weblog.csv')
            if log_file.exists():
                correlation_df = pipeline.correlate_with_logs(scan_df, str(log_file))
            else:
                correlation_df = None
            
            # Generate report
            pipeline.generate_unified_report(scan_df, correlation_df)
            
            # Export to CSV
            pipeline.export_to_csv(scan_df, 'threat_scan_analysis')
    else:
        print("[!] No scan results found. Run NetworkScanner first.")
        print("[*] Quick demo - analyzing scan results structure...")
        
        # Create demo data
        demo_df = pd.DataFrame([
            {'host': '127.0.0.1', 'port': 22, 'service': 'SSH', 'status': 'open'},
            {'host': '127.0.0.1', 'port': 80, 'service': 'HTTP', 'status': 'open'},
            {'host': '127.0.0.1', 'port': 443, 'service': 'HTTPS', 'status': 'open'},
            {'host': '127.0.0.1', 'port': 3389, 'service': 'RDP', 'status': 'open'},
        ])
        
        print("[+] Demo scan results loaded")
        pipeline.generate_unified_report(demo_df)


if __name__ == '__main__':
    main()
