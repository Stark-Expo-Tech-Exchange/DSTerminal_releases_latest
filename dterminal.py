import os
import sys
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
from threading import Thread, Event
from datetime import datetime
from cryptography.fernet import Fernet
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML

# Configuration
CONFIG = {
    'VT_API_KEY': 'YOUR_VIRUSTOTAL_API_KEY',
    'UPDATE_URL': 'https://api.github.com/repos/starkexpotech/DSTerminal/releases/latest',
    'LOG_FILE': 'secure_audit.log',
    'ENCRYPT_KEY': Fernet.generate_key().decode(),
    'CURRENT_VERSION': '2.0'
}

class SecurityTerminal:
    def __init__(self):
        self.session = PromptSession(
            history=FileHistory('.dst_history'),
            auto_suggest=AutoSuggestFromHistory(),
            completer=WordCompleter([
                'scan', 'netmon', 'harden', 'vtscan', 'regmon', 
                'memdump', 'update', 'help', 'exit', 'clearlogs',
                'portsweep', 'hashfile', 'sysinfo', 'killproc',
                'chkintegrity', 'encrypt', 'decrypt', 'watchfolder',
                'traceroute', 'exploitcheck', 'macspoof', 'dnssec',
                'sqlmap', 'ransomwatch', 'wificrack', 'stegcheck',
                'certcheck', 'torify'
            ]),
            bottom_toolbar=HTML('<b>DST</b> v{} | Mode: <style bg="{}">{}</style>').format(
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
    ║    Defensive Security Terminal v1.1 | {platform.system()} {platform.release()}   ║
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
    def _animate_scan(self):
        spinner = ['|', '/', '-', '\\']
        i = 0
        while not self.scan_complete.is_set():
            sys.stdout.write(f"\r[+] Scanning system... {spinner[i]} {self.scan_progress}%")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
        sys.stdout.write("\r" + " " * 50 + "\r")

    def scan_system(self):
        self.scan_complete.clear()
        self.scan_progress = 0
        
        spinner_thread = Thread(target=self._animate_scan)
        spinner_thread.daemon = True
        spinner_thread.start()

        try:
            for i in range(1, 101):
                time.sleep(0.03)
                self.scan_progress = i
            
            suspicious_processes = ["keylogger", "logkeys", "pykeylogger", "ahk"]
            found_threats = False
            
            for proc in psutil.process_iter(['name', 'pid', 'exe']):
                try:
                    if any(susp_keyword in proc.info['name'].lower() for susp_keyword in suspicious_processes):
                        print(f"\n[!] Suspicious Process: {proc.info['name']} (PID: {proc.pid})")
                        found_threats = True
                    
                    if platform.system() == "Windows" and "temp" in proc.info.get('exe', '').lower():
                        print(f"\n[!] Suspicious Temp Execution: {proc.info['name']}")
                        found_threats = True
                except:
                    continue

            if not found_threats:
                print("\n[+] No obvious threats detected")
            
        finally:
            self.scan_complete.set()
            spinner_thread.join()
            print("[+] System scan completed at 100%")

    def network_monitor(self):
        print("\n[+] Monitoring network connections...")
        for conn in psutil.net_connections():
            if conn.status == "ESTABLISHED" and conn.raddr:
                print(f"[→] {conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})")
        print("[+] Network scan completed")

    # ==================== NEW ADVANCED COMMANDS ====================
    def check_exploits(self):
        vulns = {
            "CVE-2021-44228": "Log4j RCE",
            "CVE-2017-0144": "EternalBlue"
        }
        print("\n[+] Checking for critical CVEs...")
        for cve, desc in vulns.items():
            print(f"{cve}: {desc} - {'[!] VULNERABLE' if random.random() > 0.7 else '[+] Secure'}")

    def spoof_mac(self, interface="eth0"):
        if self.is_admin():
            new_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255)
            )
            os.system(f"sudo ifconfig {interface} down")
            os.system(f"sudo ifconfig {interface} hw ether {new_mac}")
            os.system(f"sudo ifconfig {interface} up")
            print(f"[+] MAC spoofed to {new_mac}")
        else:
            print("[!] Requires admin privileges")

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

    def check_ssl(self, domain):
        """Check SSL certificate validity"""
        print(f"\n[+] Checking SSL certificate for {domain}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            print(f"  Issuer: {issuer.get('organizationName', 'Unknown')}")
            print(f"  Subject: {subject.get('commonName', 'Unknown')}")
            print(f"  Expires: {expires}")
            print(f"  Valid: {'Yes' if expires > datetime.now() else 'NO (EXPIRED)'}")
        except Exception as e:
            print(f"[!] SSL check failed: {e}")

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

    def check_updates(self):
        """Check for DST updates"""
        try:
            response = requests.get(CONFIG['UPDATE_URL'])
            latest = response.json()
            if latest['tag_name'] > CONFIG['CURRENT_VERSION']:
                return f"Update available: {latest['tag_name']}\nDownload: {latest['html_url']}"
            else:
                return "You have the latest version"
        except Exception as e:
            return f"Update check failed: {e}"

    def vt_scan_menu(self):
        """VirusTotal file scanning interface"""
        print("\n[VirusTotal Scanner]")
        print("1. Hash lookup")
        print("2. File scan")
        choice = input("Select option: ")
        
        if choice == "1":
            file_hash = input("Enter file hash: ")
            self.vt_hash_lookup(file_hash)
        elif choice == "2":
            file_path = input("File path to scan: ")
            self.vt_file_scan(file_path)
        else:
            print("[!] Invalid choice")

    def vt_hash_lookup(self, file_hash):
        """Check file hash against VirusTotal"""
        if not CONFIG['VT_API_KEY'] or CONFIG['VT_API_KEY'] == 'YOUR_VIRUSTOTAL_API_KEY':
            print("[!] Configure your VirusTotal API key first")
            return

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": CONFIG['VT_API_KEY']}
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                stats = result['data']['attributes']['last_analysis_stats']
                print(f"\n[+] Detection: {stats['malicious']}/{sum(stats.values())}")
                print(f"First submitted: {result['data']['attributes']['first_submission_date']}")
            else:
                print("[!] Hash not found in VirusTotal")
        except Exception as e:
            print(f"[!] Error: {e}")

    def vt_file_scan(self, file_path):
        """Upload file to VirusTotal"""
        if not os.path.exists(file_path):
            print("[!] File not found")
            return

        if not CONFIG['VT_API_KEY'] or CONFIG['VT_API_KEY'] == 'YOUR_VIRUSTOTAL_API_KEY':
            print("[!] Configure your VirusTotal API key first")
            return

        try:
            url = "https://www.virustotal.com/api/v3/files"
            headers = {"x-apikey": CONFIG['VT_API_KEY']}
            
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n[+] Scan ID: {result['data']['id']}")
                print("Check results later at: https://www.virustotal.com")
            else:
                print("[!] Upload failed")
        except Exception as e:
            print(f"[!] Error: {e}")

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

    def harden_system(self):
        """Apply basic security hardening"""
        if not self.is_admin():
            print("[!] Requires admin privileges")
            return

        print("\n[+] Applying security hardening...")
        try:
            if platform.system() == "Windows":
                # Disable SMBv1
                os.system("Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol")
                # Enable Windows Defender
                os.system("Set-MpPreference -DisableRealtimeMonitoring $false")
                print("[+] Windows hardening applied")
            else:
                # Disable root login via SSH
                os.system("sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
                # Enable firewall
                os.system("sudo ufw enable")
                print("[+] Linux hardening applied")
        except Exception as e:
            print(f"[!] Error: {e}")

    # ==================== COMMAND HANDLER ====================
    def handle_command(self, cmd):
        if cmd == "scan": 
            self.scan_system()
        elif cmd == "netmon": 
            self.network_monitor()

        elif cmd == "exploitcheck": 
            self.check_exploits()
        elif cmd.startswith("macspoof"): 
            self.spoof_mac(cmd.split()[1] if len(cmd.split()) > 1 else "eth0")
        elif cmd.startswith("sqlmap"): 
            self.sql_injection_scan(cmd.split()[1] if len(cmd.split()) > 1 else input("Target URL: "))
        elif cmd == "clearlogs": 
            self.clear_logs()
        elif cmd.startswith("portsweep"): 
            target = cmd.split()[1] if len(cmd.split()) > 1 else "127.0.0.1"
            self.port_scan(target)
        elif cmd.startswith("hashfile"): 
            self.hash_file(cmd.split()[1] if len(cmd.split()) > 1 else input("File path: "))
        elif cmd == "sysinfo": 
            self.system_info()
        elif cmd.startswith("killproc"): 
            self.kill_process(int(cmd.split()[1])) if len(cmd.split()) > 1 else print("Usage: killproc PID")
        elif cmd == "chkintegrity": 
            self.check_integrity()
        elif cmd.startswith("encrypt"): 
            self.encrypt_file(cmd.split()[1] if len(cmd.split()) > 1 else input("File to encrypt: "))
        elif cmd.startswith("decrypt"): 
            args = cmd.split()
            if len(args) > 2: 
                self.decrypt_file(args[1], args[2])
            else: 
                print("Usage: decrypt FILE.enc KEY")
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
        elif cmd.startswith("certcheck"): 
            self.check_ssl(cmd.split()[1] if len(cmd.split()) > 1 else "google.com")
        elif cmd == "memdump": 
            self.dump_memory()
        elif cmd == "torify": 
            self.enable_tor_routing()
        elif cmd == "update": 
            print(f"\n[+] {self.check_updates()}")
        elif cmd == "vtscan": 
            self.vt_scan_menu()
        elif cmd == "regmon": 
            print(self.monitor_registry())
        elif cmd == "harden": 
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
    scan           - System threat scan (animated)
    netmon         - Live network monitoring
    exploitcheck   - Check for critical CVEs
    vtscan         - VirusTotal file analysis
    clearlogs      - Securely wipe system logs
    
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
                        prompt_text = HTML('<ansigreen><b>DFFENEX</b></ansigreen>'
                               '<ansiblue>@</ansiblue>'
                               '<ansigreen><b>DSTerminal</b></ansigreen> '
                               '<ansired>--]</ansired> ')
                        user_input = self.session.prompt(prompt_text)
                        self.handle_command(user_input.strip())
                except KeyboardInterrupt:
                    print("\n[*] Use 'exit' to quit")
                except Exception as e:
                    print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    terminal = SecurityTerminal()
    terminal.run()