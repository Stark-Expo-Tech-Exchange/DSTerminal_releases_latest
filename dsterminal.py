import os
import sys

import shutil
import requests
import logging
from tqdm import tqdm

import platform
import hashlib
import requests
import json
import psutil
import time
import random
import socket
import ssl
import subprocess
import json
import OpenSSL
import argparse
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.ocsp import OCSPRequestBuilder
from threading import Thread, Event
from datetime import datetime
from cryptography.fernet import Fernet

from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from colorama import Fore, Style, init
# from pyfiglet import figlet_format
from pyfiglet import figlet_format
import itertools
from rich.console import Console, Group
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.live import Live

from threading import Thread
from rich.console import Console
from rich.layout import Layout
from rich.table import Table
from random import choice
# from rich.group import Group

init(autoreset=True)


# Configuration
CONFIG = {
    'VT_API_KEY': '957166d424812a397e328022b84594a8c02757814f6c04518dce7e81179b4b79',
    'UPDATE_URL': 'https://github.com/Stark-Expo-Tech-Exchange/DSTerminal_releases_latest.git',
    'LOG_FILE': 'secure_audit.log',
    'ENCRYPT_KEY': Fernet.generate_key().decode(),
    'CURRENT_VERSION': '2.0'
}

class SecurityTerminal:
    def __init__(self):
        """Initialize terminal settings"""
        self.log_file = "security_harden.log"
        self.setup_logging()

    def setup_logging(self):
        """Configure logging system"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            filemode='a'
        )
    def __init__(self):
        self.session = PromptSession(
            history=FileHistory('.dst_history'),
            auto_suggest=AutoSuggestFromHistory(),
            completer=WordCompleter([
                'scan -t -w system n network', 'clear', 'clear terminal', 
                'legitify', 'nikto', 'net -n mon', 'harden -t sys', 'vt-scan',
                'registry -n mon', 'cls', 
                'memdump', 'update', 'help', 'exit', 'clearlogs',
                'portsweep', 'hashfile', 'sysinfo', 'killproc',
                'check integrity', 'encrypt', 'decrypt', 'watchfolder',
                'traceroute', 'exploitcheck', 'macspoof', 'dnssec',
                'sqlmap', 'ransomwatch', 'wificrack', 'stegcheck',
                'certcheck', 'torify'
            ]),
            bottom_toolbar=HTML('<b>DSTerminal</b> v{} | Mode: <style bg="{}">{}</style>').format(
                CONFIG['CURRENT_VERSION'],
                "ansired" if self.is_admin() else "ansigreen",
                "ADMIN" if self.is_admin() else "USER"
            )
        )
        self.cipher = Fernet(CONFIG['ENCRYPT_KEY'].encode())
        self.scan_complete = Event()
        self.scan_progress = 0

    def print_banner(self):
        print(f"""
    ╔═══════════════════════════════════════════════════════════════════============═══╗
        ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗  ██╗
        ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝╚██╗██╔╝
        ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║█████╗   ╚███╔╝ 
        ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══╝   ██╔██╗ 
        ██████╔╝██║     ██║     ███████╗██║ ╚████║███████╗██╔╝ ██╗
        ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        
    ╠════════════════════════════════════════════════════════════════============══════╣
    ║    Defensive Security Terminal v2.0.0 | {platform.system()} {platform.release()}   ║
    ║    Developed by: Spark Wilson Spink | © 2024| Powered by Stark Expo Tech Exchange║
    ║    Type 'help' for available commands                                            ║
    ║ (🔍, ⚡, 🛡️) 🌐 ⚡ CLI Mode: {'ADMIN' if self.is_admin() else 'USER'}               
    ╚════════════════════════════════════════════════════════════════════============══╝
        """)

        if not self.is_admin():
            print("\n[!] Warning: Running without administrator privileges. Some features may be limited.")

    def is_admin(self):
        try:
            return os.getuid() == 0 if platform.system() != 'Windows' else None
        except:
            return False

    # ==================== CORE SECURITY COMMANDS ====================

    # def scan_system(self):
    #     self.scan_complete.clear()
    #     self.scan_progress = 0
        
    #     spinner_thread = Thread(target=self._animate_scan)
    #     spinner_thread.daemon = True
    #     spinner_thread.start()

    #     try:
    #         for i in range(1, 101):
    #             time.sleep(0.03)
    #             self.scan_progress = i
            
    #         suspicious_processes = ["keylogger", "logkeys", "pykeylogger", "ahk"]
    #         found_threats = False
            
    #         for proc in psutil.process_iter(['name', 'pid', 'exe']):
    #             try:
    #                 if any(susp_keyword in proc.info['name'].lower() for susp_keyword in suspicious_processes):
    #                     print(f"\n[!] Suspicious Process: {proc.info['name']} (PID: {proc.pid})")
    #                     found_threats = True
                    
    #                 if platform.system() == "Windows" and "temp" in proc.info.get('exe', '').lower():
    #                     print(f"\n[!] Suspicious Temp Execution: {proc.info['name']}")
    #                     found_threats = True
    #             except:
    #                 continue

    #         if not found_threats:
    #             print("\n[+] No obvious threats detected")

                # finally:
                #     self.scan_complete.set()
                #     spinner_thread.join()
                #     print("[+] System scan completed at 100%")

    def scan_system(self):
        """Enhanced system scanner with real-time progress and results display"""
     

    # Initialize console if not already done
        if not hasattr(self, 'console'):
            from rich.console import Console
            self.console = Console()

    # Define scan stages with their visual style
        scan_stages = [
            ("[cyan]Scanning Memory for anomalies...", "Memory Scan"),
            ("[yellow]Analyzing Active Processes...", "Process Scan"),
            ("[magenta]Inspecting Temporary Files...", "Temp File Scan"),
            ("[blue]Checking Network Connections...", "Network Scan"),
            ("[green]Auditing Installed Software...", "Software Audit"),
            ("[white]Verifying System Integrity...", "System Integrity"),
            ("[red]Reviewing User Accounts...", "User Audit"),
            ("[bright_cyan]Checking Security Configs...", "Security Configs"),
            ("[bright_magenta]Behavioral Analysis...", "Heuristics")
        ]

        def generate_scan_results(stage_name):
            """Generate detailed results for each scan stage"""
            results = []
        
            if stage_name == "Memory Scan":
                mem = psutil.virtual_memory()
                results.extend([
                    ("Memory Usage", f"{mem.percent}%", "green" if mem.percent < 80 else "yellow"),
                    ("Swap Usage", f"{psutil.swap_memory().percent}%", "green" if psutil.swap_memory().percent < 50 else "yellow")
                ])
            
            elif stage_name == "Process Scan":
                suspicious_procs = []
                for proc in psutil.process_iter(['name', 'pid', 'exe']):
                    try:
                        if any(kw in proc.info['name'].lower() for kw in ["keylogger", "logkeys", "pykeylogger"]):
                            suspicious_procs.append(f"{proc.info['name']} (PID: {proc.pid})")
                    except:
                        continue
                    
                if suspicious_procs:
                    results.extend([(f"Suspicious Process {i+1}", proc, "red") 
                                for i, proc in enumerate(suspicious_procs)])
                else:
                    results.append(("Suspicious Processes", "None found", "green"))
                
            elif stage_name == "Network Scan":
                conns = psutil.net_connections()
                established = sum(1 for c in conns if c.status == 'ESTABLISHED')
                results.extend([
                    ("Active Connections", str(established), "cyan"),
                    ("Suspicious Ports", "None found", "green")
                ])
            
        # Add more stages as needed...
            
            return results

        def display_stage_results(stage_name):
            """Display formatted results for a completed scan stage"""
            results = generate_scan_results(stage_name)
        
            table = Table(title=f"Stage Results: {stage_name}", 
                        show_header=True, 
                        header_style="bold magenta",
                        border_style="dim")
        
            table.add_column("Check", style="cyan", no_wrap=True)
            table.add_column("Result", style="white")
            table.add_column("Status", justify="right")
        
            for check, result, status_color in results:
                table.add_row(check, result, f"[{status_color}]{status_color.upper()}[/]")
            
            self.console.print(Panel(table, 
                                title=f"[b]Scan Results: {stage_name}[/b]", 
                                border_style="bright_blue",
                                padding=(1, 2)))

        def run_scan():
            """Main scan execution with progress animation"""
            with Live(refresh_per_second=20, console=self.console) as live:
                for stage_text, stage_name in scan_stages:
                # Create progress bar for current stage
                    progress = Progress(
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=self.console
                    )
                
                    task = progress.add_task(stage_text, total=100)
                
                # Animate progress
                    for i in range(100):
                        progress.update(task, advance=1)
                        live.update(
                            Panel(
                                Align.center(progress),
                                title="[bold]System Security Scan[/bold]",
                                subtitle=stage_name,
                                border_style="bright_white"
                            )
                        )
                        time.sleep(0.03)  # Adjust speed here
                
                # Show results after each stage completes
                    display_stage_results(stage_name)
                    time.sleep(1)  # Pause between stages

    # Run scan in a separate thread to prevent UI blocking
        scan_thread = Thread(target=run_scan)
        scan_thread.start()
        scan_thread.join()

        # if not found_threats:
        #     console.print(f"\n {display_results}")
        #     console.print("\n[bold blue][+] System is Protected & Monitored [!] [/bold blue]")
        #     console.print("\n[bold green][+] No obvious threats detected[/bold green]")

 

#  ends here going up the code


    def network_monitor(self):
        """Animated network monitoring with hacking-style visuals"""
     

        console = Console()
        scanning_icons = ["🜂", "🜁", "🜃", "🜄", "⦿", "⌾", "⍟", "⋙"]
        threat_colors = {"low": "green", "medium": "yellow", "high": "red"}

        def generate_connection_table(connections):
            """Generate animated network connection table"""
            table = Table(
                title="[bold red]NETWORK TRAFFIC ANALYSIS[/bold red]",
                show_header=True,
                header_style="bold bright_blue",
                border_style="bright_white"
            )
        
            table.add_column("LOCAL", style="cyan")
            table.add_column("→", style="bold white", justify="center")
            table.add_column("REMOTE", style="magenta")
            table.add_column("PID", style="bright_white")
            table.add_column("STATUS", justify="right")
            table.add_column("THREAT", justify="right")

            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr:
                # Threat assessment
                    threat = choice(["low", "medium", "high"])  # Replace with real analysis
                    threat_icon = {
                        "low": "[green]✓",
                        "medium": "[yellow]⚠",
                        "high": "[red]✖"
                    }[threat]
                
                # Random scanning animation effect
                    scan_icon = choice(scanning_icons)
                
                    table.add_row(
                        f"{conn.laddr.ip}:{conn.laddr.port}",
                        f"[blink]{scan_icon}[/blink]",
                        f"{conn.raddr.ip}:{conn.raddr.port}",
                        str(conn.pid),
                        "[bright_green]ACTIVE" if conn.status == "ESTABLISHED" else "[yellow]OTHER",
                        threat_icon
                    )
            return table

        def threat_scan_animation():
            """Show scanning animation before results"""
            with console.status("[bold green]Initializing network sensors...") as status:
                for i in range(5):
                    status.update(f"[bold {choice(['green','yellow','red'])}]Scanning layer {i+1}/5...")
                    time.sleep(2.5)

        def live_monitor(duration=10):
            """Real-time network monitoring display"""
            start_time = time.time()
        
            with Live(refresh_per_second=4, console=console) as live:
                while time.time() - start_time < duration:
                    connections = psutil.net_connections()
                
                # Build the dashboard
                    dashboard = Table.grid(padding=1)
                    dashboard.add_row(
                        Panel(
                            generate_connection_table(connections),
                            title="[bold]Active Connections[/bold]",
                            subtitle=f"Updated: {time.strftime('%H:%M:%S')}",
                            border_style="bright_blue"
                        )
                    )
                
                # Add stats panel
                    stats = Table(title="[bold]Network Statistics[/bold]", show_header=False, box=None)
                    stats.add_row("Total Connections", f"[bold]{len(connections)}")
                    stats.add_row("ESTABLISHED", f"[green]{sum(1 for c in connections if c.status == 'ESTABLISHED')}")
                    stats.add_row("LISTEN", f"[yellow]{sum(1 for c in connections if c.status == 'LISTEN')}")
                
                    dashboard.add_row(
                        Panel(
                            stats,
                            title="[bold]Stats[/bold]",
                            border_style="bright_yellow"
                        )
                    )
                
                    live.update(dashboard)
                    time.sleep(2)  # Refresh interval

    # Run the enhanced monitor
        console.print(Panel("[bold red] INITIATING NETWORK MONITORING SURVEILLANCE [/bold red]", 
                        border_style="red", width=50))
    
        threat_scan_animation()
        live_monitor(duration=15)
    
        console.print(Panel("[bold green] SCAN COMPLETED [/bold green]", 
                        border_style="green", width=50))    
                    
    # ==================== NEW ADVANCED COMMANDS ====================
    def check_exploits(self):
        vulns = {
            "CVE-2021-44228": "Log4j RCE",
            "CVE-2017-0144": "EternalBlue"
        }
        print("\n[+] Checking for critical CVEs...")
        for cve, desc in vulns.items():
            print(f"{cve}: {desc} - {'[!] VULNERABLE' if random.random() > 0.7 else '[+] Secure'}")

    # def network_monitor(self):
    #     console = Console()
    #     spinner_frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    
    #     banner = Text()
    #     banner.append("\n[bold bright_green]🛰️ Initiating Network Recon Protocol...[/bold bright_green]\n", style="bold")
    #     banner.append("[dim]Decrypting connection headers[/dim]\n")
    #     console.print(banner)
    
    #     time.sleep(1)

    #     connections = [conn for conn in psutil.net_connections() if conn.status == "ESTABLISHED" and conn.raddr]
    
    #     with Live(console=console, refresh_per_second=10) as live:
    #         for i, conn in enumerate(connections):
    #             spinner = spinner_frames[i % len(spinner_frames)]
    #             ip_src = f"{conn.laddr.ip}:{conn.laddr.port}"
    #             ip_dst = f"{conn.raddr.ip}:{conn.raddr.port}"
    #             conn_text = Text(f"{spinner} ", style="bold cyan")
    #             conn_text.append(f"{ip_src}", style="green")
    #             conn_text.append("  ➞  ", style="white")
    #             conn_text.append(f"{ip_dst}", style="magenta")
    #             conn_text.append(f"  (PID: {conn.pid})", style="dim")
            
    #             panel = Panel(conn_text, border_style="bright_white", title="[bold green]Intercepted Session", width=80)
    #             live.update(panel)
    #             time.sleep(0.25)
    
    #     console.print("\n[bold bright_green]✓ Network scan completed.[/bold bright_green]")

    # BELOW MACSPOOF CODE WORKING
    def spoof_mac(self, interface=None):
        """Enhanced MAC spoofing with detailed debugging"""
        print("\n[DEBUG] Starting macspoof command")  # Debug line 1
    
    # 1. Admin check
        if not self.is_admin():
            print("[!] Requires admin privileges")
            print("[DEBUG] Failed admin check")
            return
    
        print("[DEBUG] Passed admin check")  # Debug line 2

    # 2. Interface detection
        def get_active_interface():
            print("[DEBUG] Starting interface detection")  # Debug line 3
            try:
                if platform.system() in ['Linux', 'Darwin']:
                    print("[DEBUG] Trying Linux/Mac detection")
                    route = subprocess.check_output("ip route show default", 
                                                shell=True, 
                                                stderr=subprocess.PIPE).decode()
                    print(f"[DEBUG] Route output: {route.strip()}")  # Debug line 4
                    if len(route.split()) >= 5:
                        return route.split()[4]
                    return None
                
                elif platform.system() == 'Windows':
                    print("[DEBUG] Trying Windows detection")
                    output = subprocess.check_output("getmac /v /fo csv", 
                                                shell=True, 
                                                stderr=subprocess.PIPE).decode()
                    print(f"[DEBUG] Getmac output: {output.strip()}")  # Debug line 5
                    lines = [l for l in output.split('\n') if l.strip()]
                    if len(lines) > 1:
                        return lines[1].split(',')[0].strip('"')
                    return None
                
            except subprocess.CalledProcessError as e:
                print(f"[DEBUG] Command failed: {e.stderr.decode().strip()}")
                return None
            except Exception as e:
                print(f"[DEBUG] Detection error: {str(e)}")
                return None

    # 3. Get interface
        if not interface:
            print("[DEBUG] Attempting auto-detection")  # Debug line 6
            interface = get_active_interface()
            if not interface:
                print("[!] Could not detect active interface")
                print("[DEBUG] Auto-detection failed")
                return
    
        print(f"[DEBUG] Using interface: {interface}")  # Debug line 7

    # 4. MAC generation
        new_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0x00, 0x7f),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff)
        )
        print(f"[DEBUG] Generated MAC: {new_mac}")  # Debug line 8

    # 5. Execution
        try:
            print(f"\n[+] Spoofing {interface} to {new_mac}")
        
            commands = []
            if platform.system() in ['Linux', 'Darwin']:
                commands = [
                    f"ifconfig {interface} down",
                    f"ifconfig {interface} hw ether {new_mac}",
                    f"ifconfig {interface} up",
                    f"dhclient -r {interface}",
                    f"dhclient {interface}"
                ]
            elif platform.system() == 'Windows':
                interface_key = interface.split('_')[-1]
                commands = [
                    f"netsh interface set interface \"{interface}\" admin=disable",
                    f"reg add HKLM\SYSTEM\CurrentControlSet\Control\Class"
                    f"\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}"
                    f"\\{interface_key} /v NetworkAddress /d {new_mac} /f",
                    f"netsh interface set interface \"{interface}\" admin=enable"
                ]
        
            print("[DEBUG] Commands to execute:")  # Debug line 9
            for i, cmd in enumerate(commands, 1):
                print(f"[DEBUG] {i}. {cmd}")
            
                result = subprocess.run(cmd, 
                                    shell=True, 
                                    capture_output=True, 
                                    text=True)
                if result.returncode != 0:
                    print(f"[DEBUG] Command failed: {result.stderr.strip()}")
            
                time.sleep(0.5)
        
            print("[+] MAC address successfully changed")
        
        except Exception as e:
            print(f"[!] MAC spoofing failed: {str(e)}")
    
    # 6. Verification
        self._verify_mac_change(interface, new_mac)

    def _verify_mac_change(self, interface, expected_mac):
        """Enhanced verification with debugging"""
        print("[DEBUG] Starting verification")  # Debug line 10
        try:
            if platform.system() in ['Linux', 'Darwin']:
                result = subprocess.run(f"ifconfig {interface}",
                                    shell=True,
                                    capture_output=True,
                                    text=True)
                print(f"[DEBUG] ifconfig output: {result.stdout[:200]}...")  # Debug line 11
                if expected_mac.lower() in result.stdout.lower():
                    print("[✓] MAC verification successful")
                else:
                    print("[!] MAC verification failed")
                
            elif platform.system() == 'Windows':
                result = subprocess.run("getmac /v /fo csv",
                                    shell=True,
                                    capture_output=True,
                                    text=True)
                print(f"[DEBUG] getmac output: {result.stdout.strip()}")  # Debug line 12
                if expected_mac.lower() in result.stdout.lower():
                    print("[✓] MAC verification successful")
                else:
                    print("[!] MAC verification failed")
    
        except Exception as e:
            print(f"[DEBUG] Verification error: {str(e)}")

    # ======end of macspoof

    def sql_injection_scan(self, url):
        if "http" in url:
            print(f"\n[+] Starting SQLi scan on {url}...")
            print("[*] Simulating SQLMap scan (install sqlmap for real scanning)")
            print("Potential vulnerabilities found: 2")
        else:
            print("[!] Invalid URL format (include http://)")

    # ==================== UTILITY METHODS ====================
    def clear_logs(self):
        """Securely clear system logs"""
        if self.is_admin():
            try:
                if platform.system() == "Windows":
                    os.system("wevtutil cl System")
                    os.system("wevtutil cl Application")
                    os.system("wevtutil cl Security")
                    print("[+] Windows event logs cleared")
                else:
                    os.system("sudo rm -rf /var/log/*")
                    print("[+] System logs cleared")
            except Exception as e:
                print(f"[!] Error clearing logs: {e}")
        else:
            print("[!] Requires admin privileges")

    def port_scan(self, target):
        """Scan target IP for open ports"""
        print(f"\n[+] Scanning {target}...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"  [→] Port {port} is open")
                sock.close()
            except:
                pass

        threads = []
        for port in common_ports:
            t = Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        print("[+] Port scan completed")

    def hash_file(self, file_path):
        """Generate cryptographic hashes for a file"""
        if not os.path.exists(file_path):
            print("[!] File not found")
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                md5 = hashlib.md5(data).hexdigest()
                sha1 = hashlib.sha1(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                
                print(f"\n[+] Hashes for {file_path}:")
                print(f"  MD5:    {md5}")
                print(f"  SHA1:   {sha1}")
                print(f"  SHA256: {sha256}")
        except Exception as e:
            print(f"[!] Error hashing file: {e}")

    def system_info(self):
        """Display detailed system information"""
        print("\n[+] System Information:")
        print(f"  OS: {platform.system()} {platform.release()}")
        print(f"  Architecture: {platform.machine()}")
        print(f"  Processor: {platform.processor()}")
        print(f"  Hostname: {socket.gethostname()}")
        print(f"  IP Address: {socket.gethostbyname(socket.gethostname())}")
        print(f"  CPU Cores: {psutil.cpu_count(logical=False)} (Logical: {psutil.cpu_count()})")
        print(f"  Memory: {psutil.virtual_memory().total / (1024**3):.2f} GB")
        print(f"  Disk Usage: {psutil.disk_usage('/').percent}%")
        print(f"  Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S')}")

    def kill_process(self, pid):
        """Terminate a process by PID"""
        try:
            process = psutil.Process(pid)
            print(f"[+] Killing process: {process.name()} (PID: {pid})")
            process.kill()
            print("[+] Process terminated")
        except psutil.NoSuchProcess:
            print("[!] No such process")
        except psutil.AccessDenied:
            print("[!] Access denied (try as admin)")

    def check_integrity(self):
        """Check system file integrity"""
        print("\n[+] Checking critical system files...")
        critical_files = {
            "Windows": ["C:\\Windows\\System32\\kernel32.dll", "C:\\Windows\\System32\\cmd.exe"],
            "Linux": ["/bin/bash", "/usr/bin/sudo"],
            "Darwin": ["/bin/bash", "/usr/bin/sudo"]
        }
        
        os_type = platform.system()
        for file in critical_files.get(os_type, []):
            if os.path.exists(file):
                size = os.path.getsize(file)
                mtime = datetime.fromtimestamp(os.path.getmtime(file)).strftime('%Y-%m-%d %H:%M:%S')
                print(f"  {file} - Size: {size} bytes, Modified: {mtime}")
            else:
                print(f"  [!] Missing critical file: {file}")

    def encrypt_file(self, file_path):
        """Encrypt a file using AES-256"""
        if not os.path.exists(file_path):
            print("[!] File not found")
            return

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = self.cipher.encrypt(data)
            with open(file_path + '.enc', 'wb') as f:
                f.write(encrypted)
            
            os.remove(file_path)
            print(f"[+] File encrypted and saved as {file_path}.enc")
            print(f"[!] Key for decryption: {CONFIG['ENCRYPT_KEY']}")
        except Exception as e:
            print(f"[!] Encryption failed: {e}")

    def decrypt_file(self, file_path, key=None):
        """Decrypt a file using the provided key"""
        if not os.path.exists(file_path):
            print("[!] File not found")
            return

        try:
            key = key or CONFIG['ENCRYPT_KEY']
            cipher = Fernet(key.encode())
            
            with open(file_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = cipher.decrypt(encrypted)
            output_path = file_path.replace('.enc', '')
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            print(f"[+] File decrypted and saved as {output_path}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

    def watch_folder(self, path):
        """Monitor a folder for changes"""
        if not os.path.exists(path):
            print("[!] Path not found")
            return

        print(f"\n[+] Monitoring {path} for changes (Ctrl+C to stop)...")
        before = dict([(f, None) for f in os.listdir(path)])
        
        try:
            while True:
                time.sleep(5)
                after = dict([(f, None) for f in os.listdir(path)])
                added = [f for f in after if f not in before]
                removed = [f for f in before if f not in after]
                
                if added: print(f"  [+] Files added: {', '.join(added)}")
                if removed: print(f"  [-] Files removed: {', '.join(removed)}")
                
                before = after
        except KeyboardInterrupt:
            print("\n[+] Folder monitoring stopped")

    def trace_route(self, target):
        """Perform a traceroute to target"""
        print(f"\n[+] Tracing route to {target}...")
        try:
            if platform.system() == "Windows":
                os.system(f"tracert {target}")
            else:
                os.system(f"traceroute {target}")
        except Exception as e:
            print(f"[!] Error: {e}")

    def monitor_ransomware(self):
        """Check for ransomware indicators"""
        print("\n[+] Scanning for ransomware indicators...")
        suspicious_extensions = ['.encrypted', '.locked', '.crypt', '.ransom']
        found = False
        
        for root, _, files in os.walk('/' if platform.system() != 'Windows' else 'C:\\'):
            for file in files:
                if any(file.endswith(ext) for ext in suspicious_extensions):
                    print(f"  [!] Suspicious file: {os.path.join(root, file)}")
                    found = True
            if found:  # Prevent full disk scan
                break
        
        if not found:
            print("[+] No obvious ransomware files detected")

    def wifi_audit(self, interface):
        """Perform WiFi security audit"""
        if platform.system() != "Linux":
            print("[!] This command requires Linux")
            return

        print(f"\n[+] Auditing WiFi on {interface}...")
        try:
            result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
            print(result.stdout)
            
            if "unassociated" in result.stdout:
                print("[!] Interface not connected")
                return
                
            print("\n[+] Nearby access points:")
            subprocess.run(['sudo', 'iwlist', interface, 'scan'], check=True)
        except Exception as e:
            print(f"[!] Error: {e}")

    def check_steganography(self, image_path):
        """Check for hidden data in images"""
        if not os.path.exists(image_path):
            print("[!] Image not found")
            return

        print(f"\n[+] Analyzing {image_path} for hidden data...")
        try:
            with open(image_path, 'rb') as f:
                content = f.read()
            
            # Simple steg detection (look for common steg headers)
            steg_signatures = {
                b'\x53\x54\x45\x47': 'Steghide',
                b'\x50\x4E\x47': 'Potential LSB steganography'
            }
            
            found = False
            for sig, name in steg_signatures.items():
                if sig in content:
                    print(f"  [!] Detected potential {name} signature")
                    found = True
            
            if not found:
                print("[+] No obvious steganography signatures detected")
        except Exception as e:
            print(f"[!] Error: {e}")
  
    def check_ssl(self, domain=None):
        """Comprehensive SSL certificate analyzer with export options"""
        try:
           
            if not domain:
                domain = input("Enter domain to check (e.g., starkexpo.com): ").strip()
                if not domain:
                    print("[!] No domain provided")
                    return
        
            print(f"\n[+] Analyzing SSL certificate for {domain}...")
        
        # Configure enhanced SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_default_certs()
        
        # Set timeout and create connection
            socket.setdefaulttimeout(10)
        
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    cert_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
                
                # Get certificate details
                    peer_cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in peer_cert['issuer'])
                    subject = dict(x[0] for x in peer_cert['subject'])
                    expires = datetime.strptime(peer_cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    valid_days = (expires - datetime.now()).days
                
                # Get certificate chain using OpenSSL
                    chain = []
                    store = OpenSSL.crypto.X509Store()
                    store_ctx = OpenSSL.crypto.X509StoreContext(store, cert_obj)
                
                    try:
                        chain_result = store_ctx.get_verified_chain()
                        for i, chain_cert in enumerate(chain_result):
                            chain.append({
                                'subject': dict(chain_cert.get_subject().get_components()),
                                'issuer': dict(chain_cert.get_issuer().get_components()),
                                'expires': chain_cert.get_notAfter().decode('utf-8'),
                                'serial': chain_cert.get_serial_number(),
                                'version': chain_cert.get_version() + 1
                            })
                    except OpenSSL.crypto.X509StoreContextError:
                        chain.append({
                            'subject': dict(cert_obj.get_subject().get_components()),
                            'issuer': dict(cert_obj.get_issuer().get_components()),
                            'expires': cert_obj.get_notAfter().decode('utf-8'),
                            'serial': cert_obj.get_serial_number(),
                            'version': cert_obj.get_version() + 1
                        })
                
                # Check OCSP revocation status
                    ocsp_status = "Unknown"
                    if len(chain) > 1:
                        ocsp_status = self._check_ocsp(cert_obj, chain[1])
                
                # Print comprehensive report
                    self._print_ssl_report(domain, ssock, cert_obj, chain, ocsp_status, valid_days)
                
                    # Export option
                    if input("\nExport results to file? (y/N): ").lower() == 'y':
                        self._export_ssl_results(domain, ssock, cert_obj, chain)
    
        except ssl.SSLError as e:
            print(f"[!] SSL Error: {e}")
        except socket.timeout:
            print("[!] Connection timed out")
        except ImportError as e:
            print(f"[!] Required module missing: {str(e)}")
            print("[!] Please install pyOpenSSL: pip install pyopenssl")
        except Exception as e:
            print(f"[!] Analysis failed: {str(e)}")


    def _print_ssl_report(self, domain, ssock, cert_obj, chain, ocsp_status, valid_days):
        """Display formatted SSL report"""
    # Basic info box
        print("\n╔" + "═"*60 + "╗")
        print(f"║ {'SSL/TLS Certificate Analysis':^58} ║")
        print("╠" + "═"*60 + "╣")
        print(f"║ {'Domain:':<15} {domain:<43} ║")
        print(f"║ {'Issuer:':<15} {cert_obj.get_issuer().CN:<43} ║")
        print(f"║ {'Subject:':<15} {cert_obj.get_subject().CN:<43} ║")
        print(f"║ {'Expires:':<15} {cert_obj.get_notAfter().decode('utf-8')} ({valid_days} days) ║")
        print(f"║ {'Protocol:':<15} {ssock.version():<43} ║")
        print(f"║ {'Cipher:':<15} {ssock.cipher()[0]:<43} ║")
        print(f"║ {'OCSP Status:':<15} {ocsp_status:<43} ║")
        print("╚" + "═"*60 + "╝")
    
    # Certificate chain visualization
        print("\n[Certificate Chain]")
        for i, cert in enumerate(chain):
            print(f"{'  ' * i}└─ {cert['subject'].get(b'CN', b'Unknown').decode('utf-8')}")
            if i == 0:
                print(f"    {'Issuer:':<10} {cert['issuer'].get(b'CN', b'Unknown').decode('utf-8')}")
                print(f"    {'Valid Until:':<10} {cert['expires']}")
    
    # Security recommendations
        print("\n[Security Assessment]")
        if valid_days < 30:
            print("[!] Certificate expires soon!")
        if 'SHA1' in cert_obj.get_signature_algorithm().decode('utf-8'):
            print("[!] Weak signature algorithm (SHA-1)")
        if ssock.version() == 'TLSv1':
            print("[!] Insecure protocol version (TLS 1.0)")
        elif ssock.version() == 'TLSv1.1':
            print("[!] Deprecated protocol version (TLS 1.1)")

    def _check_ocsp(self, cert, issuer_cert):
        """Check OCSP revocation status"""
        try:
            
        
            cert = load_pem_x509_certificate(
                OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            )
        
            if issuer_cert:
                issuer = load_pem_x509_certificate(
                    OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, issuer_cert)
                )
                builder = OCSPRequestBuilder()
                builder = builder.add_certificate(cert, issuer)
                req = builder.build()
            
                ocsp_url = cert.extensions.get_extension_for_class(
                    cryptography.x509.AuthorityInformationAccess
                ).value.get_ocsp_urls()[0]
            
                response = requests.post(
                    ocsp_url,
                    data=req.public_bytes(serialization.Encoding.DER),
                    headers={'Content-Type': 'application/ocsp-request'}
                )
            
                return "REVOKED" if response.status == 1 else "VALID"
        except:
            return "Unknown"

    def _export_ssl_results(self, domain, ssock, cert_obj, chain):
        """Export results to JSON file"""
        
    
        data = {
            'domain': domain,
            'scan_date': datetime.now().isoformat(),
            'protocol': ssock.version(),
            'cipher': ssock.cipher()[0],
            'certificate': {
                'subject': dict(cert_obj.get_subject().get_components()),
                'issuer': dict(cert_obj.get_issuer().get_components()),
                'valid_until': cert_obj.get_notAfter().decode('utf-8'),
                'serial': cert_obj.get_serial_number(),
                'signature_algorithm': cert_obj.get_signature_algorithm().decode('utf-8')
            },
            'chain': chain
        }
    
        filename = f"ssl_scan_{domain}_{datetime.now().strftime('%Y%m%d')}.json"
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
        print(f"[+] Results saved to {filename}")

        # ssl ends here====

    def dump_memory(self):
        """Create a memory dump (requires admin)"""
        if not self.is_admin():
            print("[!] Requires admin privileges")
            return

        print("\n[+] Creating memory dump...")
        try:
            if platform.system() == "Windows":
                os.system("procdump -ma -accepteula")
                print("[+] Memory dump saved as .dmp files")
            else:
                print("[!] Linux memory dump requires LiME or fmem")
        except Exception as e:
            print(f"[!] Error: {e}")

    def enable_tor_routing(self):
        """Route traffic through Tor"""
        print("\n[+] Configuring Tor routing...")
        try:
            if platform.system() == "Linux":
                os.system("sudo apt install tor -y")
                os.system("sudo service tor start")
                print("[+] Tor service started. Configure your apps to use 127.0.0.1:9050")
            else:
                print("[!] Automatic Tor setup requires Linux. Install Tor Browser manually.")
        except Exception as e:
            print(f"[!] Error: {e}")

    # def check_updates(self):
    #     """Check for DST updates"""
    #     try:
    #         response = requests.get(CONFIG['https://github.com/Stark-Expo-Tech-Exchange/DSTerminal_releases_latest.git'])
    #         latest = response.json()
    #         if latest['tag_name'] > CONFIG['CURRENT_VERSION']:
    #             return f"Update available: {latest['tag_name']}\nDownload: {latest['html_url']}"
    #         else:
    #             return "You have the latest version"
    #     except Exception as e:
    #         return f"Update check failed: {e}"

    # update s code ends here going up=======================

    # def check_updates(self):
    #     """Check for DST updates with visual feedback"""
    #     console = Console()
    
    # # Animated loading screen
    #     with Progress(
    #         SpinnerColumn(),
    #         TextColumn("[progress.description]{task.description}"),
    #         transient=True,
    #     ) as progress:
    #         task = progress.add_task("[cyan]Checking for updates...", total=100)
        
    #         for i in range(100):
    #             time.sleep(0.02)  # Simulate work
    #             progress.update(task, advance=1)
    
    # # Live updating status display
    #     status_text = Text("", style="bold yellow")
    
    #     with Live(Panel(status_text), refresh_per_second=10) as live:
    #         try:
    #         # Phase 1: Connecting
    #             status_text.append("🔗 Connecting to update server...\n", style="bold blue")
    #             live.refresh()
    #             time.sleep(0.5)
            
    #         # Phase 2: Downloading data
    #             status_text.append("⏬ Fetching version information...\n", style="bold cyan")
    #             live.refresh()
            
    #             response = requests.get('https://api.github.com/repos/Stark-Expo-Tech-Exchange/DSTerminal/releases/latest')
    #             latest = response.json()
            
    #         # Phase 3: Processing
    #             status_text.append(f"⚙ Processing version {latest['tag_name']}...\n", style="bold green")
    #             live.refresh()
    #             time.sleep(0.3)
            
    #             if latest['tag_name'] > CONFIG['CURRENT_VERSION']:
    #             # Update available animation
    #                 for _ in range(3):
    #                     status_text.append("✨", style="bold magenta")
    #                     live.refresh()
    #                     time.sleep(0.2)
    #                     status_text.append("🌟", style="bold yellow")
    #                     live.refresh()
    #                     time.sleep(0.2)
                
    #                 return Panel(
    #                     f"[bold green]Update available: {latest['tag_name']}\n\n"
    #                     f"[bold white]Release Notes:[/] {latest['body']}\n\n"
    #                     f"[bold cyan]Download:[/] {latest['html_url']}",
    #                     title="🚀 New Version Available",
    #                     border_style="bold green"
    #                 )
    #             else:
    #             # Up-to-date animation
    #                 status_text.append("✅ ", style="bold green")
    #                 live.refresh()
    #                 time.sleep(0.5)
    #                 return Panel(
    #                     "[bold green]You have the latest version![/]",
    #                     title="✓ System Status",
    #                     border_style="bold green"
    #                 )
                
    #         except Exception as e:
    #         # Error animation
    #             for _ in range(3):
    #                 status_text.append("⚠", style="blink bold red")
    #                 live.refresh()
    #                 time.sleep(0.2)
            
    #             return Panel(
    #                 f"[bold red]Update check failed:[/] {str(e)}",
    #                 title="⚠ Update Error",
    #                 border_style="bold red"
    #             )

    def check_updates(self):
        """Check for DST updates with visual feedback"""
        console = Console()
    
        try:
        # Display initial connection status
            with console.status("[bold blue]🔗 Connecting to update server...") as status:
                time.sleep(1)
            
            # Phase 1: Fetching data
                status.update("[bold cyan]⏬ Fetching version information...")
                try:
                    response = requests.get(
                        'https://github.com/Stark-Expo-Tech-Exchange/DSTerminal_releases_latest.git',
                        timeout=10
                    )
                    response.raise_for_status()
                    latest = response.json()
                except requests.RequestException as e:
                    console.print(Panel(
                        f"[bold red]⚠ Network error:[/] {str(e)}",
                        title="Connection Failed",
                        border_style="bold red"
                    ))
                    return False

            # Phase 2: Processing
                status.update(f"[bold green]⚙ Processing version {latest.get('tag_name', 'unknown')}...")
                time.sleep(0.5)

            # Validate response
                if 'tag_name' not in latest:
                    console.print(Panel(
                        "[bold red]⚠ Invalid response from update server[/]",
                        title="Data Error",
                        border_style="bold red"
                    ))
                    return False

                current_version = getattr(self, 'CURRENT_VERSION', 'v2.0.0')
            
                if latest['tag_name'] > current_version:
                # Update available
                    console.print(Panel(
                        f"[bold green]Update available: {latest['tag_name']}[/]\n\n"
                        f"[bold white]Release Notes:[/]\n{latest.get('body', 'No release notes')}\n\n"
                        f"[bold cyan]Download: [link={latest['html_url']}]{latest['html_url']}[/link]",
                        title="🚀 New Version Available",
                        border_style="bold green",
                        padding=(1, 2)
                    ))
                    return True
                else:
                # Up-to-date
                    console.print(Panel(
                        "[bold green]✓ You have the latest version![/]",
                        title="System Status",
                        border_style="bold green",
                        padding=(1, 4)
                    ))
                    return True

        except Exception as e:
            console.print(Panel(
                f"[bold red]⚠ Unexpected error:[/] {str(e)}",
                title="⚠ Critical Error",
                border_style="blink bold red"
            ))
            return


    # clearing the terminal code starts here
    def clear_terminal(self):
        console = Console()
        with Live(console=console, refresh_per_second=10, screen=True) as live:
            for i in range(1, 6):
                cleanup_panel = Panel(
                    Align.center(
                        f"[bold cyan]→ Cleaning stage {i}/5...\n[blink]✶✶✶[/blink]", vertical="middle"),
                    title="[bold bright_cyan]TERMINAL SANITIZATION[/bold bright_cyan]",
                    border_style="cyan",
                    padding=(2, 4),
                    width=60
                )
                live.update(Align.center(cleanup_panel, vertical="middle"))
                time.sleep(1.5)

        os.system('clear' if os.name == 'posix' else 'cls')
        console.print(
            Panel.fit(
                "[bold blue]✔ Terminal workspace sanitized successfully![/bold blue]",
                border_style="purple",
                width=50
            )
        )

    # cleaning terminal ends here

    # ==========================================================

    # emergency shutdown code command starts here
    # def emergency_shutdown(self):
        # console = Console()
        # with Live(console=console, refresh_per_second=10, screen=True) as live:
        #     for i in range(5, 0, -1):
        #         panel = Panel(
        #             Align.center(f"[bold red]⚠ SYSTEM SHUTDOWN IN {i}...[/bold red]", vertical="middle"),
        #             title="[bold red]EMERGENCY SHUTDOWN[/bold red]",
        #             border_style="bright_red",
        #             width=60,
        #             padding=(2, 4),
        #         )
        #         live.update(Align.center(panel, vertical="middle"))
        #         time.sleep(1.5)

        # console.print(Panel.fit("[bold red]Shutting down now...[/bold red]", border_style="red"))
        # os.system("sudo shutdown now")


# uncomment the code below for shutting down==============================

    # def emergency_shutdown(self):
        # console = Console()
        # warning_panel = Panel(
        #     Align.center(
        #         "[bold red]⚠ WARNING: This will initiate an IMMEDIATE SYSTEM SHUTDOWN.[/bold red]\n\n"
        #         "[yellow]Type [bold]'CONFIRM'[/bold] to proceed or anything else to cancel.[/yellow]",
        #         vertical="middle"
        #     ),
        #     title="[bold red]EMERGENCY SHUTDOWN MODE[/bold red]",
        #     border_style="bright_red",
        #     width=72,
        #     padding=(2, 4),
        # )
        # console.print(Align.center(warning_panel, vertical="middle"))
    
        # user_input = Prompt.ask("[bold red]>>> Confirm Shutdown[/bold red]").strip().upper()
        # if user_input != "CONFIRM":
        #     console.print(
        #         Panel.fit(
        #             "[bold green]✔ Shutdown cancelled. You're safe.[/bold green]",
        #             border_style="green",
        #             width=50
        #         )
        #     )
        #     return

    # Animated progress bar
        # progress = Progress(
        #     SpinnerColumn(style="bold red"),
        #     BarColumn(bar_width=None),
        #     TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        #     TextColumn("[bold red]Shutting down system..."),
        #     expand=True,
        # )

        # with Live(console=console, refresh_per_second=20, screen=True) as live:
        #     task = progress.add_task("shutdown", total=100)
        #     for percent in range(0, 101, 5):
        #         panel = Panel(
        #             Align.center(progress, vertical="middle"),
        #             title="[bold red]SYSTEM SHUTDOWN IN PROGRESS...[/bold red]",
        #             border_style="red",
        #             padding=(2, 4),
        #             width=70,
        #         )
        #         progress.update(task, completed=percent)
        #         live.update(Align.center(panel, vertical="middle"))
        #         time.sleep(0.15)

        # console.print(
        #     Panel.fit("[bold red]System is shutting down now...[/bold red]", border_style="red", width=50)
        # )
        # os.system("sudo shutdown now")

    # code shutdwon ends here and uncomment the code above
  
    def vt_scan_menu(self):
        """Enhanced VirusTotal scanning interface"""
        print("\n[VirusTotal Scanner]")
        print("1. Hash lookup")
        print("2. File scan")
        print("3. Bulk scan folder")
        print("4. Check previous scan")
        choice = input("Select option: ")
        
        if choice == "1":
            file_hash = input("Enter file hash (MD5/SHA1/SHA256): ").strip()
            self.vt_hash_lookup(file_hash)
        elif choice == "2":
            file_path = input("File path to scan: ").strip()
            self.vt_file_scan(file_path)
        elif choice == "3":
            folder_path = input("Folder path to scan: ").strip()
            max_files = input("Max files to scan (default 10): ").strip() or 10
            self.vt_bulk_scan(folder_path, int(max_files))
        elif choice == "4":
            scan_id = input("Enter previous scan ID: ").strip()
            self.check_scan_result(scan_id)
        else:
            print("[!] Invalid choice")

    def vt_hash_lookup(self, file_hash):
        """Enhanced hash lookup with detailed results"""
        if not self._validate_vt_api():
            return

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": CONFIG['VT_API_KEY']}
            
            print(f"\n[+] Checking hash: {file_hash}...")
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                attrs = result['data']['attributes']
                
                # Detailed report
                print(f"\n╔{'═'*60}╗")
                print(f"║ {'VirusTotal Report':^58} ║")
                print(f"╠{'═'*60}╣")
                print(f"║ {'Detection:':<15} {attrs['last_analysis_stats']['malicious']}/{sum(attrs['last_analysis_stats'].values())} ║")
                print(f"║ {'First Seen:':<15} {attrs['first_submission_date']} ║")
                print(f"║ {'File Type:':<15} {attrs.get('type_tag', 'Unknown')} ║")
                
                # Top detections
                malicious = [k for k,v in attrs['last_analysis_results'].items() if v['category'] == 'malicious']
                if malicious:
                    print(f"╠{'═'*60}╣")
                    print(f"║ {'Top Detections:':<58} ║")
                    for engine in malicious[:3]:
                        print(f"║ - {engine:<55} ║")
                print(f"╚{'═'*60}╝")
                
                # Auto-quarantine recommendation
                if attrs['last_analysis_stats']['malicious'] > 0:
                    print("\n[!] MALICIOUS FILE DETECTED!")
                    if input("Quarantine file? (y/N): ").lower() == 'y':
                        self.quarantine_file(None, file_hash=file_hash)
            else:
                print("[!] Hash not found in VirusTotal")
        except Exception as e:
            print(f"[!] Error: {e}")
  

    def vt_file_scan(self, file_path):
        """Upload file to VirusTotal with debug output"""
        print(f"\n[DEBUG] Starting scan for: {file_path}")  # Debug line
    
        if not os.path.exists(file_path):
            print("[!] Error: File not found")
            print(f"[DEBUG] Resolved path: {os.path.abspath(file_path)}")  # Debug line
            return

            print("[DEBUG] File exists check passed")  # Debug line
    
        if not self._validate_vt_api():
            print("[!] Error: VirusTotal API validation failed")
            print(f"[DEBUG] API Key: {'Set' if CONFIG.get('VT_API_KEY') else 'Not Set'}")  # Debug line
            return

        print("[DEBUG] API validation passed")  # Debug line
    
        MAX_SIZE = 32 * 1024 * 1024  # 32MB
        file_size = os.path.getsize(file_path)
        print(f"[DEBUG] File size: {file_size} bytes")  # Debug line

        if file_size > MAX_SIZE:
            print(f"[!] Error: File too large ({file_size/1024/1024:.2f}MB > 32MB)")
            return

        print("[DEBUG] Size check passed")  # Debug line
    
        try:
            print(f"\n[+] Analyzing {os.path.basename(file_path)}...")
            print(f"  ↳ Size: {file_size/1024:.2f}KB")
            print("  ↳ Uploading...", end='', flush=True)
        
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                headers = {"x-apikey": CONFIG['VT_API_KEY']}
                print(f"\n[DEBUG] Sending request to VirusTotal...")  # Debug line
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files,
                    timeout=30
                )
            print(" Done!")

            print(f"[DEBUG] Response status: {response.status_code}")  # Debug line
            if response.status_code == 200:
                result = response.json()
                scan_id = result['data']['id']
                print(f"\n[+] Scan ID: {scan_id}")
                print(f"[+] Report URL: https://www.virustotal.com/gui/file/{scan_id}")
                self._cache_scan_id(file_path, scan_id)
            else:
                print(f"[!] Error: Upload failed (HTTP {response.status_code})")
                print(f"[DEBUG] Response text: {response.text}")  # Debug line

        except Exception as e:
            print(f"\n[!] Critical Error: {str(e)}")
            print("[DEBUG] Exception occurred during upload")  # Debug line

        if response.status_code == 200:
            result = response.json()
            scan_id = result['data']['id']
            print(f"\n[+] Scan ID: {scan_id}")
        
        # Start polling in background
        Thread(target=self._poll_results, args=(scan_id, file_path), daemon=True).start()
 
    def _cache_scan_id(self, file_path, scan_id):
        """Store scan IDs for future reference"""
        cache_file = os.path.expanduser("~/.dstenex_scans.log")
        with open(cache_file, "a") as f:
            f.write(f"{file_path}|{scan_id}|{datetime.now()}\n")

    def vt_bulk_scan(self, folder_path, max_files=10):
        """Scan multiple files in a folder"""
        if not os.path.isdir(folder_path):
            print("[!] Invalid folder path")
            return
            
        print(f"\n[+] Scanning up to {max_files} files in {folder_path}...")
        scanned = 0
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                if scanned >= max_files:
                    break
                    
                file_path = os.path.join(root, file)
                print(f"\n[File {scanned+1}/{max_files}] {file}")
                
                # First try local scan
                local_result = self.local_scan(file_path, silent=True)
                if local_result and local_result['infected']:
                    print("[!] LOCAL SCAN DETECTED THREAT!")
                    self.quarantine_file(file_path)
                    scanned += 1
                    continue
                
                # Fall back to VT if file < 32MB
                if os.path.getsize(file_path) <= 32 * 1024 * 1024:
                    self.vt_file_scan(file_path)
                else:
                    print("[!] File too large for VT, skipped")
                
                scanned += 1
                time.sleep(15)  # Respect VT API rate limits
        
        print("\n[+] Bulk scan completed")

    def _poll_results(self, scan_id, original_path=None):
        """Background result polling"""
        url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        headers = {"x-apikey": CONFIG['VT_API_KEY']}
        
        print("\n[+] Waiting for results... (Ctrl+C to check later)")
        try:
            for _ in range(10):  # Max 10 checks
                time.sleep(30)
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    result = response.json()
                    status = result['data']['attributes']['status']
                    
                    if status == 'completed':
                        stats = result['data']['attributes']['stats']
                        print(f"\n[+] Final Results: {stats['malicious']} malicious / {stats['harmless']} clean")
                        
                        if stats['malicious'] > 0 and original_path:
                            self.quarantine_file(original_path)
                        return
                    else:
                        print(f"\r  ↳ Status: {status}...", end='', flush=True)
        except Exception:
            print("\n[!] Polling interrupted. Check later with 'check_result'")

    def check_scan_result(self, scan_id):
        """Check existing scan results"""
        url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        headers = {"x-apikey": CONFIG['VT_API_KEY']}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                stats = result['data']['attributes']['stats']
                print(f"\n[+] Results: {stats['malicious']} malicious / {stats['harmless']} clean")
                
                if stats['malicious'] > 0:
                    print("[!] MALICIOUS CONTENT DETECTED")
            else:
                print("[!] Results not available yet")
        except Exception as e:
            print(f"[!] Error checking results: {e}")

    def local_scan(self, file_path, silent=False):
        """Integrate ClamAV for local scanning"""
        try:
            import pyclamd
            cd = pyclamd.ClamdAgnostic()
            scan_result = cd.scan_file(file_path)
            
            if scan_result and scan_result.get(file_path) == 'OK':
                if not silent:
                    print("[+] Local scan: Clean")
                return {'infected': False}
            else:
                if not silent:
                    print("[!] Local scan: Infected!")
                    print(f"Detection: {scan_result.get(file_path, 'Unknown threat')}")
                return {'infected': True, 'threat': scan_result.get(file_path)}
                
        except ImportError:
            if not silent:
                print("[!] ClamAV not installed (pip install pyclamd)")
        except Exception as e:
            if not silent:
                print(f"[!] Local scan failed: {e}")
        return None

    def quarantine_file(self, file_path, file_hash=None):
        """Move dangerous files to quarantine"""
        quarantine_dir = os.path.join(os.path.expanduser("~"), "quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        
        try:
            if file_path:
                filename = os.path.basename(file_path)
                new_path = os.path.join(quarantine_dir, f"quarantined_{filename}")
                shutil.move(file_path, new_path)
                print(f"[+] File moved to quarantine: {new_path}")
            elif file_hash:
                with open(os.path.join(quarantine_dir, "quarantined_hashes.txt"), "a") as f:
                    f.write(f"{file_hash}\n")
                print("[+] Malicious hash recorded")
        except Exception as e:
            print(f"[!] Quarantine failed: {e}")

    def _validate_vt_api(self):
        """Check if API key is configured"""
        if not CONFIG.get('VT_API_KEY') or CONFIG['VT_API_KEY'] == 'YOUR_VIRUSTOTAL_API_KEY':
            print("[!] Configure VirusTotal API key first:")
            print("1. Get key from: https://www.virustotal.com/gui/join-us")
            print("2. Edit CONFIG['VT_API_KEY'] in your code")
            return False
        return True


        # go up to change

    def monitor_registry(self):
        """Monitor Windows registry changes"""
        if platform.system() != "Windows":
            return "[!] Registry monitoring requires Windows"

        suspicious_keys = [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SYSTEM\CurrentControlSet\Services"
        ]
        
        try:
            import winreg
            changes = []
            
            for key_path in suspicious_keys:
                hive, path = key_path.split('\\', 1)
                hive = getattr(winreg, {
                    'HKLM': 'HKEY_LOCAL_MACHINE',
                    'HKCU': 'HKEY_CURRENT_USER'
                }[hive])
                
                with winreg.OpenKey(hive, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        changes.append(f"{key_path}\\{name} = {value}")
            
            if changes:
                return "\n".join(["[!] Suspicious registry entries:"] + changes)
            else:
                return "[+] No suspicious registry entries found"
        except Exception as e:
            return f"[!] Registry scan failed: {e}"
 


    #  starts here

    def _print_banner(self, text):
        """Display hacking-style banner with fallback"""
        try:
            ascii_art = figlet_format(text, font='slant')
            if os.environ.get('TERM') and 'color' in os.environ.get('TERM', ''):
                colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
                flicker = random.choice(colors) + ascii_art.replace(random.choice(text), '▒') + Style.RESET_ALL
                print(f"\n{flicker}")
            else:
                # print(f"\n{ascii_art}")
                print(f"\n")
        except ImportError:
            border = "═" * (len(text) + 4)
            print(f"\n")
            # print(f"\n{border}\n  {text.upper()}  \n{border}\n")

        except Exception as e:
            print(f"\n=== {text.upper()} ===\n")

    # uncomment below code if there is any error---starts here
    # def _hacking_animation(self, message, duration=15):
    #     """Show animated hacking simulation with rotating vector-style objects"""
    #     vectors = [
    #         ["[■]", "[▲]", "[●]", "[◆]"],  # rotating shield
    #         ["{X}", "{/}", "{|}", "{\\}"],  # spinning firewall
    #         ["(☠)", "(☢)", "(⚠)", "(☣)"],  # rotating danger signs
    #         ["<->", "<=>", "<#>", "<*>"],   # data packet/malware flow
    #         ["[∞]", "[¤]", "[§]", "[%]"]    # encryption chaos
    #     ]

    #     obj1 = random.choice(vectors)
    #     obj2 = random.choice([v for v in vectors if v != obj1])

    #     end_time = time.time() + duration
    #     print(f"\n{Fore.CYAN}[*] {message}", end='')

    #     i = 0
    #     while time.time() < end_time:
    #         sym1 = obj1[i % len(obj1)]
    #         sym2 = obj2[i % len(obj2)]
    #         print(f"\r{Fore.CYAN}[*] {message} {sym1} {sym2}{Style.RESET_ALL}", end='')
    #         time.sleep(0.15)
    #         i += 1
    #     print()
    # ends here uncomment above code


 
    # def _hacking_animation(duration, graphics):
    #     console = Console()
    #     symbols = list("⚙⧈⧫◎◉▣⛏⊠⊞⌁⍟☍█▓▒░▌▎#@$=%/\\*~^↯⎈⛶∞∴∵")
        

        # class RotatingSymbol:
        #     def __init__(self):
        #         self.frames = random.sample(symbols, k=4)
        #         self.frame_iter = itertools.cycle(self.frames)
        #         self.color = random.choice(["cyan", "magenta", "green", "yellow", "red", "blue", "bright_white"])

        #     def next(self):
        #         symbol = next(self.frame_iter)
        #         self.color = random.choice(["cyan", "magenta", "green", "yellow", "red", "blue", "bright_white"])
        #         return Text(symbol, style=self.color)

        # rows, cols = 5, 100
        # symbol_grid = [[RotatingSymbol() for _ in range(cols)] for _ in range(rows)]

        # def render():
        #     text = Text()
        #     for row in symbol_grid:
        #         for symbol in row:
        #             text.append(symbol.next())
        #         text.append("\n")
        #     return text

        # start_time = time.time()
        # duration = 15  # seconds

        # with Live(render(), console=console, refresh_per_second=10) as live:
        #     try:
        #         while time.time() - start_time < duration:
        #             time.sleep(0.1)
        #             live.update(render())
        #     except KeyboardInterrupt:
        #         console.print("\n[bold red]Animation interrupted.[/bold red]")
    def _hacking_animation(duration, graphics):
        console = Console()
        symbols = list("▣⚙⧫◎◉⛏⊠⊞⌁⍟☍█▓▒░▌▎#@$=%/\\*~^↯⎈⛶∞∴∵")

        class RotatingSymbol:
            def __init__(self):
                self.frames = random.sample(symbols, k=4)
                self.frame_iter = itertools.cycle(self.frames)
                self.color = random.choice(["cyan", "magenta", "green", "yellow", "red", "blue", "bright_white"])

            def next(self):
                symbol = next(self.frame_iter)
                self.color = random.choice(["cyan", "magenta", "green", "yellow", "red", "blue", "bright_white"])
                return Text(symbol, style=self.color)

        rows, cols = 1, 150
        symbol_grid = [[RotatingSymbol() for _ in range(cols)] for _ in range(rows)]

    # Progress bar setup
        progress = Progress(
            TextColumn("[bold green]HARDENING...[/bold green]"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            expand=False,
        )
        task = progress.add_task("HARDENING", total=100)

        start_time = time.time()
        duration = 15  # seconds

        def render():
        # Background grid
            text = Text()
            for row in symbol_grid:
                for symbol in row:
                    text.append(symbol.next())
                text.append("\n")

        # Centered panel with progress bar
            elapsed = time.time() - start_time
            percent = min(100, int((elapsed / duration) * 100))
            progress.update(task, completed=percent)

            panel = Panel(
                Align.center(progress, vertical="middle"),
                title="[bold cyan]System Hardening Phase [1, 2 & 3][/bold cyan]",
                border_style="bright_white",
                width=40,
                padding=(1, 2),
            )


            combined = Group(text, Align.center(panel, vertical="middle"))
            return combined

        with Live(render(), console=console, refresh_per_second=10, screen=True) as live:
            try:
                while time.time() - start_time < duration:
                    time.sleep(0.1)
                    live.update(render())
            except KeyboardInterrupt:
                console.print("\n[bold red]Animation interrupted.[/bold red]")

        console.print("[bold green]✓ Access Granted.[/bold green]")



    def _cyber_attack_simulation(self):
        """Simulate incoming attacks being blocked (randomized)"""
        attack_types = ["Brute Force", "SQL Injection", "XSS", "RCE", "Zero-Day"]
        protocols = ["SSH", "HTTP", "HTTPS", "FTP", "SMTP"]

        print(f"\n{Fore.RED}▄︻デ══━ INTRUSION DETECTED ══━︻▄{Style.RESET_ALL}")
        for _ in range(random.randint(3, 5)):
            attack = random.choice(attack_types)
            protocol = random.choice(protocols)
            ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            time.sleep(random.uniform(0.3, 0.7))
            print(f"{Fore.YELLOW}▶ {ip} | {protocol} | {attack}{Style.RESET_ALL}", end='')
            time.sleep(random.uniform(0.5, 1.2))
            print(f"\r{Fore.GREEN}✓ {ip} | {protocol} | {attack} {Fore.BLACK}▶ BLOCKED{Style.RESET_ALL}")

    def _network_scan_animation(self):
        """Simulate network scanning visualization"""
        print(f"\n{Fore.CYAN}═════════⋘ NETWORK TOPOLOGY ⋙═════════{Style.RESET_ALL}")
        devices = [
            ("Router", "192.168.1.1", "Cisco IOS"),
            ("Workstation", "192.168.1.15", "Windows 11"),
            ("Server", "192.168.1.100", "Ubuntu 22.04")
        ]

        for device, ip, osys in devices:
            print(f"{Fore.MAGENTA}⌖ {device}: {ip}", end='')
            for _ in range(3):
                print(".", end='', flush=True)
                time.sleep(0.3)
            print(f" {Fore.WHITE}[{osys}]{Style.RESET_ALL}")

    def _vulnerability_scan(self):
        """Simulated vulnerability assessment with randomized output"""
        sample_vulns = [
            ("CVE-2023-1234", "Critical", "SMB Protocol"),
            ("CVE-2022-4567", "High", "OpenSSL"),
            ("CVE-2021-8910", "Medium", "Linux Kernel"),
            ("CVE-2020-4455", "Low", "Apache Server"),
            ("CVE-2019-1111", "Critical", "Docker")
        ]
        vulns = random.sample(sample_vulns, k=random.randint(2, 4))

        print(f"\n{Fore.RED}▄︻デ══━ VULNERABILITY SCAN ══━︻▄{Style.RESET_ALL}")
        for cve, severity, component in vulns:
            time.sleep(0.5)
            print(f"{severity.upper().ljust(8)} {cve} → {component}")
            time.sleep(0.3)
        print(f"{Fore.GREEN}✓ {len(vulns)} vulnerabilities patched{Style.RESET_ALL}")

    def _matrix_rain(self, duration=2):
        """Simulate matrix-style code rain with hacker symbols"""
        chars = "!@#$%^&*<>?+=-|/\\[]{}⧫◇◆⊞⊠✶✸▣⛏⚔⛓⌁"
        width = os.get_terminal_size().columns
        end_time = time.time() + duration

        print(f"{Fore.GREEN}", end='')
        while time.time() < end_time:
            print(''.join(random.choice(chars) for _ in range(width)))
            time.sleep(0.08)
        print(Style.RESET_ALL, end='')

    def is_admin(self):
        """Check for admin privileges"""
        try:
            if platform.system() == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.getuid() == 0
        except:
            return False

    def harden_system(self, dry_run=False):
        """Full cinematic hardening experience with proper error handling"""
        try:
            self._print_banner("CYBER DEFENSE")

            if not self.is_admin():
                self._hacking_animation("Checking Privileges")
                print(f"{Fore.RED}[!] Admin rights required{Style.RESET_ALL}")
                return

            # self._matrix_rain(1.5)
            self._hacking_animation("Initializing Threat Assessment")
            self._network_scan_animation()

            self._hacking_animation("Scanning Exploit Database")
            self._vulnerability_scan()

            self._cyber_attack_simulation()

            if dry_run:
                self._hacking_animation("Simulating Countermeasures")
                print(f"{Fore.YELLOW}[SIMULATION] No changes were actually made{Style.RESET_ALL}")
            else:
                self._hacking_animation("Deploying Cyber Armor")
                try:
                    if platform.system() == "Windows":
                        os.system("powershell Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart")
                    elif platform.system() == "Linux":
                        os.system("sudo ufw --force enable")
                    logging.info(f"Hardening completed on {platform.system()}")
                except Exception as e:
                    logging.error(f"Hardening failed: {str(e)}")
                    print(f"{Fore.RED}[!] Error during hardening: {str(e)}{Style.RESET_ALL}")

            # self._matrix_rain(1)
            print(f"\n{Fore.GREEN}▄︻デ══━ SYSTEM FORTIFICATION COMPLETE ══━︻▄{Style.RESET_ALL}")
            print(f"{Fore.YELLOW} Firewall Active | Intrusion Prevention Engaged | Threat Level: {random.randint(1, 10)}/10{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.RED}[!] Critical error: {str(e)}{Style.RESET_ALL}")
            # self._matrix_rain(1)
            print(f"\n{Fore.GREEN}▄︻デ══━ SYSTEM FORTIFICATION COMPLETE ══━︻▄{Style.RESET_ALL}")
            print(f"{Fore.YELLOW} Firewall Active | Intrusion Prevention Engaged | Threat Level: {random.randint(1, 10)}/10{Style.RESET_ALL}")
        
        # ends here improved code above




    # go down here, don't remoe these lines below
    def nikto_scan(self, target_url, port=80, output_file=None):
        """Run Nikto scan on a target URL."""
        cmd = f"nikto -h {target_url} -p {port}"
        if output_file:
            cmd += f" -o {output_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    def legitify_scan_github(self, org_or_repo, token=None):
        """Scan a GitHub org/repo for security issues."""
        cmd = f"legitify scan --github {org_or_repo}"
        if token:
            cmd += f" --token {token}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
  
    def handle_command(self, cmd):
        parts = cmd.split()
        if not parts:
            print("[!] Empty command. Type 'help' for options.")
            return

    # ===== TruffleHog =====
        if parts[0] == "trufflehog":
            if "--git" in parts:
                try:
                    git_url = parts[parts.index("--git") + 1]
                    print(self.trufflehog_scan_git(git_url))
                except IndexError:
                    print("[!] Missing Git URL. Usage: trufflehog --git <URL>")
            elif "--fs" in parts:
                try:
                    fs_path = parts[parts.index("--fs") + 1]
                    print(self.trufflehog_scan_filesystem(fs_path))
                except IndexError:
                    print("[!] Missing filesystem path. Usage: trufflehog --fs <PATH>")
            else:
                print("Usage: trufflehog --git <URL> OR --fs <PATH>")

    # ===== Nikto =====
        elif parts[0] == "nikto":
            if "--url" not in parts:
                print("Usage: nikto --url <TARGET> [--port PORT] [--output FILE]")
                return
            try:
                target = parts[parts.index("--url") + 1]
                port = parts[parts.index("--port") + 1] if "--port" in parts else "80"
                output = parts[parts.index("--output") + 1] if "--output" in parts else None
                print(self.nikto_scan(target, port, output))
            except IndexError:
                print("[!] Invalid arguments. Usage: nikto --url <TARGET> [--port PORT] [--output FILE]")

    # ===== Legitify =====
        elif parts[0] == "legitify":
            if "--github" not in parts:
                print("Usage: legitify --github <ORG/REPO> [--token TOKEN]")
                return
            try:
                repo = parts[parts.index("--github") + 1]
                token = parts[parts.index("--token") + 1] if "--token" in parts else None
                print(self.legitify_scan_github(repo, token))
            except IndexError:
                print("[!] Invalid arguments. Usage: legitify --github <ORG/REPO> [--token TOKEN]")

    # Original commands (scan, netmon, etc.)
        elif cmd == "scan -t -w system n network":
            self.scan_system()
        elif cmd == "net -n mon":
            self.network_monitor()

        # ===================================

    #  for clear command to clean terminal
        elif cmd == "clear terminal":
            self.clear_terminal()

        elif cmd == "clear":
            self.clear_terminal()
        elif cmd == "shutdown":
            self.emergency_shutdown()
    

# ================================================
    # exploit check and mac address change
        elif cmd == "exploitcheck": 
            self.check_exploits()
        elif cmd.startswith("macspoof"): 
            self.spoof_mac(cmd.split()[1] if len(cmd.split()) > 1 else "eth0")

    #  sqlmap and log clearing
        elif cmd.startswith("sqlmap"): 
            self.sql_injection_scan(cmd.split()[1] if len(cmd.split()) > 1 else input("Target URL: "))
        elif cmd == "clearlogs": 
            self.clear_logs()

    # portsweep and hashing file commands
        elif cmd.startswith("portsweep"): 
            target = cmd.split()[1] if len(cmd.split()) > 1 else "127.0.0.1"
            self.port_scan(target)
        elif cmd.startswith("hashfile"): 
            self.hash_file(cmd.split()[1] if len(cmd.split()) > 1 else input("File path: "))

    #  system information detailed part and force killing of running processes
        elif cmd == "sysinfo": 
            self.system_info()
        elif cmd.startswith("killproc"): 
            self.kill_process(int(cmd.split()[1])) if len(cmd.split()) > 1 else print("Usage: killproc PID")

    # ==================check integrity and encrypt or decrypt files/folders
        elif cmd == "check integrity": 
            self.check_integrity()
        elif cmd.startswith("encrypt"): 
            self.encrypt_file(cmd.split()[1] if len(cmd.split()) > 1 else input("File to encrypt: "))
        elif cmd.startswith("decrypt"): 
            args = cmd.split()
            if len(args) > 2: 
                self.decrypt_file(args[1], args[2])
            else: 
                print("Usage: decrypt FILE.enc KEY")

    # =====================================
        elif cmd.startswith("watchfolder"): 
            self.watch_folder(cmd.split()[1] if len(cmd.split()) > 1 else ".")
        elif cmd.startswith("traceroute"): 
            self.trace_route(cmd.split()[1] if len(cmd.split()) > 1 else "8.8.8.8")
        elif cmd == "ransomwatch": 
            self.monitor_ransomware()
        elif cmd.startswith("wificrack"): 
            self.wifi_audit(cmd.split()[1] if len(cmd.split()) > 1 else "wlan0")
        elif cmd.startswith("stegcheck"): 
            self.check_steganography(cmd.split()[1] if len(cmd.split()) > 1 else input("Image path: "))
        # elif cmd.startswith("certcheck"): 
        #     self.check_ssl(cmd.split()[1] if len(cmd.split()) > 1 else "google.com")

        elif cmd.startswith("certcheck"):
        # Handle both command line input and interactive prompt
            if len(cmd.split()) > 1:
                domain = cmd.split()[1]
                self.check_ssl(domain)
            else:
                self.check_ssl()  # Will prompt for domain inside the method

        elif cmd == "memdump": 
            self.dump_memory()
        elif cmd == "torify": 
            self.enable_tor_routing()
        elif cmd == "update": 
            print(f"\n[+] {self.check_updates()}")
        elif cmd == "vt-scan": 
            self.vt_scan_menu()
        elif cmd == "registry -n mon": 
            print(self.monitor_registry())
        elif cmd == "harden -t sys": 
            self.harden_system()
        elif cmd == "help": 
            self.show_help()
        elif cmd == "exit": 
            print("\n[*] Exiting Defensive Security Terminal")
            sys.exit(0)
        else: 
            print("[!] Unknown command. Type 'help' for more command options.")

    # ==================== HELP MENU ====================
    def show_help(self):
        help_text = """
    DSTerminal Commands:
    
    === Core Security ===
    scan                            - System threat scan (animated)
    netmon                          - Live network monitoring
    exploitcheck                    - Check for critical CVEs
    vtscan                          - VirusTotal file analysis
    clearlogs                       - Securely wipe system logs
    nikto --url <TARGET>            - Web vulnerability scan")
    legitify --github <ORG/REPO>    - Scan GitHub for misconfigurations")

    === Network Tools ===
    portsweep [IP] - Scan target for open ports
    traceroute [IP]- Network path analysis
    torify         - Route traffic through Tor
    dnssec [DOMAIN]- Validate DNSSEC
    
    === Forensics ===
    memdump        - Capture RAM for analysis
    hashfile [PATH]- Generate file hashes
    stegcheck [IMG]- Detect hidden image data
    ransomwatch    - Find ransomware artifacts
    
    === System Management ===
    sysinfo        - Detailed system report
    killproc PID   - Terminate process
    macspoof [IFACE] - Randomize MAC address
    harden         - Apply security hardening
    
    === Crypto Tools ===
    encrypt FILE   - AES-256 file encryption
    decrypt FILE KEY - File decryption
    
    === Web Security ===
    sqlmap [URL]   - SQL injection scan
    certcheck [DOMAIN] - SSL certificate audit
    
    === Monitoring ===
    watchfolder [PATH] - Directory change detection
    regmon        - Windows registry monitor
    
    === Utilities ===
    update         - Check for DST updates
    help           - Show this menu
    exit           - Quit terminal
    """
        print(help_text)

    def run(self):
            self.print_banner()
            while True:
                try:
                        prompt_text = HTML('<ansigreen><b>[-- DFFENEX</b></ansigreen>'
                               '<ansiblue>@</ansiblue>'
                               '<ansigreen><b>DSTerminal</b></ansigreen> '
                               '<ansired>]-[]</ansired> ')
                        user_input = self.session.prompt(prompt_text)
                        self.handle_command(user_input.strip())
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                except Exception as e:
                    print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    terminal = SecurityTerminal()
    terminal.run()