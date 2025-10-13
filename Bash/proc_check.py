#!/usr/bin/env python3

"""
Process Validation Tool
Version: 1.0
Description: Validates running processes against /proc entries to detect security anomalies
Author: Security Team
Usage: ./proc_check.py [options]
"""

import os
import sys
import subprocess
import argparse
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import re

# Version information
VERSION = "1.0"
COPYRIGHT = "Copyright (c) 2024 Security Team"

# Color codes for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'  # No Color

class ProcessValidator:
    """Main class for process validation and anomaly detection"""
    
    def __init__(self, verbose=False, quiet=False, log_file=None):
        self.verbose = verbose
        self.quiet = quiet
        self.log_file = log_file
        self.anomalies = []
        self.proc_dir = Path('/proc')
        
        # Setup logging
        self.setup_logging()
        
        # Validate environment
        if not self.proc_dir.exists():
            self.log_error("Error: /proc directory not found. This script requires Linux.")
            sys.exit(1)
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = logging.INFO if self.verbose else logging.WARNING
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Add file handler if specified
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(logging.INFO)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            logging.getLogger().addHandler(file_handler)
    
    def log_info(self, message):
        """Log info message"""
        logging.info(message)
        if not self.quiet:
            print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")
    
    def log_warn(self, message):
        """Log warning message"""
        logging.warning(message)
        if not self.quiet:
            print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")
    
    def log_error(self, message):
        """Log error message"""
        logging.error(message)
        if not self.quiet:
            print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")
    
    def log_success(self, message):
        """Log success message"""
        logging.info(message)
        if not self.quiet:
            print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {message}")
    
    def run_ps_command(self) -> List[Dict]:
        """Execute ps command and parse output"""
        try:
            # Use ps with specific format for better parsing
            cmd = ['ps', '-eo', 'pid,ppid,cmd', '--no-headers']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            processes = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                # Parse ps output - format: PID PPID CMD
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    pid = int(parts[0])
                    ppid = int(parts[1])
                    cmd = parts[2]
                    
                    processes.append({
                        'pid': pid,
                        'ppid': ppid,
                        'cmd': cmd
                    })
            
            self.log_info(f"Found {len(processes)} processes from ps command")
            return processes
            
        except subprocess.CalledProcessError as e:
            self.log_error(f"Failed to execute ps command: {e}")
            return []
        except Exception as e:
            self.log_error(f"Error parsing ps output: {e}")
            return []
    
    def get_proc_processes(self) -> List[Dict]:
        """Get process information from /proc directory"""
        processes = []
        
        try:
            # Iterate through /proc directories
            for proc_entry in self.proc_dir.iterdir():
                if not proc_entry.is_dir() or not proc_entry.name.isdigit():
                    continue
                
                pid = int(proc_entry.name)
                proc_info = self.parse_proc_entry(proc_entry)
                
                if proc_info:
                    processes.append(proc_info)
            
            self.log_info(f"Found {len(processes)} processes from /proc directory")
            return processes
            
        except Exception as e:
            self.log_error(f"Error reading /proc directory: {e}")
            return []
    
    def parse_proc_entry(self, proc_path: Path) -> Optional[Dict]:
        """Parse individual /proc entry for process information"""
        try:
            pid = int(proc_path.name)
            proc_info = {'pid': pid}
            
            # Read /proc/PID/status for basic info
            status_file = proc_path / 'status'
            if status_file.exists():
                with open(status_file, 'r') as f:
                    for line in f:
                        if line.startswith('PPid:'):
                            proc_info['ppid'] = int(line.split()[1])
                            break
            
            # Read /proc/PID/cmdline for command line
            cmdline_file = proc_path / 'cmdline'
            if cmdline_file.exists():
                with open(cmdline_file, 'rb') as f:
                    cmdline_bytes = f.read()
                    # cmdline is null-separated, replace nulls with spaces
                    cmdline = cmdline_bytes.replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                    proc_info['cmdline'] = cmdline
            
            # Read /proc/PID/exe symlink for executable path
            exe_file = proc_path / 'exe'
            if exe_file.exists():
                try:
                    proc_info['exe_path'] = os.readlink(str(exe_file))
                except OSError:
                    proc_info['exe_path'] = None
            
            # Read /proc/PID/cwd for current working directory
            cwd_file = proc_path / 'cwd'
            if cwd_file.exists():
                try:
                    proc_info['cwd'] = os.readlink(str(cwd_file))
                except OSError:
                    proc_info['cwd'] = None
            
            return proc_info
            
        except Exception as e:
            self.log_error(f"Error parsing /proc/{proc_path.name}: {e}")
            return None
    
    def check_executable_exists(self, exe_path: str) -> bool:
        """Check if executable file exists and is accessible"""
        if not exe_path:
            return False
        
        try:
            # Handle deleted executables (common in /proc/exe)
            if ' (deleted)' in exe_path:
                return False
            
            # Check if file exists
            return os.path.exists(exe_path) and os.access(exe_path, os.R_OK)
        except Exception:
            return False
    
    def normalize_command(self, cmd: str) -> str:
        """Normalize command for comparison"""
        if not cmd:
            return ""
        
        # Remove extra whitespace and normalize paths
        cmd = ' '.join(cmd.split())
        
        # Remove common variations that don't affect functionality
        # This is a basic normalization - could be enhanced
        return cmd.strip()
    
    def compare_processes(self, ps_processes: List[Dict], proc_processes: List[Dict]) -> None:
        """Compare processes from ps and /proc to detect anomalies"""
        
        # Create lookup dictionaries for easier comparison
        ps_dict = {p['pid']: p for p in ps_processes}
        proc_dict = {p['pid']: p for p in proc_processes}
        
        # Get all PIDs
        all_pids = set(ps_dict.keys()) | set(proc_dict.keys())
        
        self.log_info(f"Comparing {len(all_pids)} total processes")
        
        for pid in sorted(all_pids):
            ps_proc = ps_dict.get(pid)
            proc_proc = proc_dict.get(pid)
            
            # Check for hidden processes
            if proc_proc and not ps_proc:
                self.add_anomaly("hidden_process", pid, 
                    f"Process exists in /proc but missing in ps output")
                continue
            
            # Check for processes in ps but not in /proc
            if ps_proc and not proc_proc:
                self.add_anomaly("missing_proc", pid,
                    f"Process in ps output but missing from /proc")
                continue
            
            # Both exist - compare details
            self.compare_process_details(pid, ps_proc, proc_proc)
    
    def compare_process_details(self, pid: int, ps_proc: Dict, proc_proc: Dict) -> None:
        """Compare detailed information between ps and /proc entries"""
        
        # Compare command lines
        ps_cmd = self.normalize_command(ps_proc.get('cmd', ''))
        proc_cmdline = self.normalize_command(proc_proc.get('cmdline', ''))
        
        if ps_cmd != proc_cmdline:
            self.add_anomaly("edited_command", pid,
                f"Command line mismatch - PS: '{ps_cmd[:100]}...' vs PROC: '{proc_cmdline[:100]}...'")
        
        # Check executable file
        exe_path = proc_proc.get('exe_path')
        if exe_path and not self.check_executable_exists(exe_path):
            self.add_anomaly("missing_file", pid,
                f"Executable file missing or inaccessible: {exe_path}")
        
        # Check for suspicious patterns
        self.check_suspicious_patterns(pid, ps_proc, proc_proc)
    
    def check_suspicious_patterns(self, pid: int, ps_proc: Dict, proc_proc: Dict) -> None:
        """Check for suspicious patterns that might indicate compromise"""
        
        # Check for processes with no command line
        cmdline = proc_proc.get('cmdline', '').strip()
        if not cmdline:
            self.add_anomaly("anomaly", pid,
                "Process has empty command line")
        
        # Check for processes with unusual executable paths
        exe_path = proc_proc.get('exe_path', '')
        if exe_path:
            # Check for executables in suspicious locations
            suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/proc/']
            if any(exe_path.startswith(path) for path in suspicious_paths):
                self.add_anomaly("anomaly", pid,
                    f"Executable in suspicious location: {exe_path}")
            
            # Check for processes with deleted executables
            if ' (deleted)' in exe_path:
                self.add_anomaly("anomaly", pid,
                    f"Process running deleted executable: {exe_path}")
        
        # Check for processes with unusual working directories
        cwd = proc_proc.get('cwd', '')
        if cwd:
            suspicious_cwd = ['/tmp/', '/var/tmp/', '/dev/shm/']
            if any(cwd.startswith(path) for path in suspicious_cwd):
                self.add_anomaly("anomaly", pid,
                    f"Process running from suspicious directory: {cwd}")
        
        # Check for processes with very long command lines (potential obfuscation)
        if len(cmdline) > 1000:
            self.add_anomaly("anomaly", pid,
                f"Unusually long command line ({len(cmdline)} chars)")
        
        # Check for processes with binary data in command line
        try:
            cmdline.encode('ascii')
        except UnicodeEncodeError:
            self.add_anomaly("anomaly", pid,
                "Command line contains binary data")
    
    def add_anomaly(self, anomaly_type: str, pid: int, description: str) -> None:
        """Add an anomaly to the results"""
        anomaly = {
            'type': anomaly_type,
            'pid': pid,
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        self.anomalies.append(anomaly)
        
        # Log the anomaly
        self.log_warn(f"ANOMALY [{anomaly_type.upper()}] PID {pid}: {description}")
    
    def print_summary(self) -> None:
        """Print summary of findings"""
        if self.quiet:
            return
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.NC}")
        print(f"{Colors.CYAN}Process Validation Summary{Colors.NC}")
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
        
        if not self.anomalies:
            print(f"{Colors.GREEN}✓ No anomalies detected{Colors.NC}")
            print(f"{Colors.GREEN}All processes appear to be normal{Colors.NC}")
        else:
            print(f"{Colors.RED}⚠ Found {len(self.anomalies)} anomaly(ies):{Colors.NC}")
            
            # Group anomalies by type
            anomaly_counts = {}
            for anomaly in self.anomalies:
                anomaly_type = anomaly['type']
                anomaly_counts[anomaly_type] = anomaly_counts.get(anomaly_type, 0) + 1
            
            for anomaly_type, count in sorted(anomaly_counts.items()):
                print(f"  {Colors.YELLOW}{anomaly_type.replace('_', ' ').title()}: {count}{Colors.NC}")
        
        print(f"{Colors.CYAN}{'='*60}{Colors.NC}")
    
    def save_results(self, output_file: str) -> None:
        """Save results to file"""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'total_anomalies': len(self.anomalies),
                'anomalies': self.anomalies
            }
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.log_info(f"Results saved to {output_file}")
            
        except Exception as e:
            self.log_error(f"Failed to save results: {e}")
    
    def run_validation(self) -> int:
        """Run the complete process validation"""
        try:
            self.log_info("Starting process validation...")
            
            # Get processes from both sources
            ps_processes = self.run_ps_command()
            proc_processes = self.get_proc_processes()
            
            if not ps_processes and not proc_processes:
                self.log_error("No processes found from either source")
                return 1
            
            # Compare processes
            self.compare_processes(ps_processes, proc_processes)
            
            # Print summary
            self.print_summary()
            
            # Return exit code based on findings
            return 2 if self.anomalies else 0
            
        except Exception as e:
            self.log_error(f"Validation failed: {e}")
            return 1

def show_help():
    """Display help information"""
    help_text = f"""
Process Validation Tool v{VERSION}

Description:
    Validates running processes against /proc entries to detect security anomalies.
    This tool compares process information from ps command with /proc entries to
    identify potential rootkits, hidden processes, or system compromises.

Usage:
    {sys.argv[0]} [options]

Options:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -q, --quiet             Suppress all output except errors
    -l, --log FILE          Log results to specified file
    -o, --output FILE       Save detailed results to JSON file
    -V, --version           Show version information

Examples:
    {sys.argv[0]}                          # Basic validation
    {sys.argv[0]} -v                       # Verbose output
    {sys.argv[0]} -l validation.log        # Log to file
    {sys.argv[0]} -o results.json          # Save JSON results
    {sys.argv[0]} -v -l log.txt -o out.json # Full logging and output

Anomaly Types Detected:
    hidden_process          Process exists in /proc but missing in ps output
    edited_command          Command line in ps differs from /proc/cmdline
    missing_file            Executable file is missing or inaccessible
    missing_proc            Process in ps output but missing from /proc
    anomaly                 Other suspicious patterns or behaviors

Exit Codes:
    0 - No anomalies detected
    1 - Error occurred
    2 - Anomalies found

Security Notes:
    - This tool requires root privileges for full functionality
    - Some legitimate processes may trigger false positives
    - Always verify findings before taking action
    - Use in conjunction with other security tools

{VERSION} - {COPYRIGHT}
"""
    print(help_text)

def show_version():
    """Display version information"""
    print(f"Process Validation Tool v{VERSION}")
    print(COPYRIGHT)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Process Validation Tool - Detect security anomalies in running processes",
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='store_true',
                       help='Show help message')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Suppress all output except errors')
    parser.add_argument('-l', '--log', type=str,
                       help='Log results to specified file')
    parser.add_argument('-o', '--output', type=str,
                       help='Save detailed results to JSON file')
    parser.add_argument('-V', '--version', action='store_true',
                       help='Show version information')
    
    args = parser.parse_args()
    
    # Handle help and version
    if args.help:
        show_help()
        return 0
    
    if args.version:
        show_version()
        return 0
    
    # Validate arguments
    if args.quiet and args.verbose:
        print(f"{Colors.RED}Error: Cannot use both --quiet and --verbose{Colors.NC}")
        return 1
    
    # Create validator and run
    try:
        validator = ProcessValidator(
            verbose=args.verbose,
            quiet=args.quiet,
            log_file=args.log
        )
        
        # Run validation
        exit_code = validator.run_validation()
        
        # Save results if requested
        if args.output:
            validator.save_results(args.output)
        
        return exit_code
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Validation interrupted by user{Colors.NC}")
        return 1
    except Exception as e:
        print(f"{Colors.RED}Unexpected error: {e}{Colors.NC}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
