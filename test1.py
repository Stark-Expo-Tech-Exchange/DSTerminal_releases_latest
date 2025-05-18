# import os
# import sys
# import platform
# import hashlib
# import requests
# import json
# import psutil
# import time
# from threading import Thread, Event
# from datetime import datetime
# from prompt_toolkit import PromptSession, HTML
# from prompt_toolkit.history import FileHistory
# from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
# from prompt_toolkit.completion import WordCompleter
# from cryptography.fernet import Fernet

# # Configuration
# CONFIG = {
#     'VT_API_KEY': 'YOUR_VIRUSTOTAL_API_KEY',
#     'UPDATE_URL': 'https://api.github.com/repos/starkexpotech/DSTerminal/releases/latest',
#     'LOG_FILE': 'secure_audit.log',
#     'ENCRYPT_KEY': Fernet.generate_key().decode(),
#     'CURRENT_VERSION': '1.2'
# }

# class SecurityTerminal:
#     def __init__(self):
#         self.session = PromptSession(
#             history=FileHistory('.dst_history'),
#             auto_suggest=AutoSuggestFromHistory(),
#             completer=WordCompleter([
#                 'scan', 'netmon', 'harden', 'vtscan',
#                 'regmon', 'memdump', 'update', 'help', 'exit'
#             ]),
#             bottom_toolbar=HTML('<b>DST</b> v{} | Mode: <style bg="{}">{}</style>').format(
#                 CONFIG['CURRENT_VERSION'],
#                 "ansired" if self.is_admin() else "ansigreen",
#                 "ADMIN" if self.is_admin() else "USER"
#             )
#         )
#         self.cipher = Fernet(CONFIG['ENCRYPT_KEY'].encode())
#         self.scan_complete = Event()
#         self.scan_progress = 0

#     def print_banner(self):
#         print(f"""
#          _____ _             _____           _____         _____          _____
#         /  ___| |           |  __ \         |_   _|       |  _  |        |____ |
#         \ `--.| |_ __ _ _ __| |  \/ ___ _ __  | | ___  ___| | | |_ __ ___    / /
#          `--. \ __/ _` | '__| | __ / _ \ '_ \ | |/ _ \/ __| | | | '_ ` _ \   \ \\
#         /\__/ / || (_| | |  | |_\ \  __/ | | || |  __/\__ \ \_/ / | | | | |.__/ /
#         \____/ \__\__,_|_|   \____/\___|_| |_\___/\___|___/\___/|_| |_| |_\____/™
#         {'=' * 70}
#         Defensive Security Terminal v{CONFIG['CURRENT_VERSION']} | {platform.system()} {platform.release()}
#         Developed by: Stark Expo Tech Exchange™ | © 2024
#         {'=' * 70}
#         Type 'help' for available commands
#         """)

#         if not self.is_admin():
#             print("\n[!] Warning: Running without administrator privileges. Some features may be limited.")

#     def is_admin(self):
#         try:
#             return os.getuid() == 0 if platform.system() != 'Windows' else None
#         except:
#             return False

#     def _animate_scan(self):
#         spinner = ['|', '/', '-', '\\']
#         i = 0
#         while not self.scan_complete.is_set():
#             sys.stdout.write(f"\r[+] Scanning system... {spinner[i]} {self.scan_progress}%")
#             sys.stdout.flush()
#             time.sleep(0.1)
#             i = (i + 1) % 4
#         sys.stdout.write("\r" + " " * 50 + "\r")  # Clear line

#     def scan_system(self):
#         self.scan_complete.clear()
#         self.scan_progress = 0
        
#         # Start animation thread
#         spinner_thread = Thread(target=self._animate_scan)
#         spinner_thread.daemon = True
#         spinner_thread.start()

#         try:
#             # Simulate scan progress
#             for i in range(1, 101):
#                 time.sleep(0.03)  # Simulate work
#                 self.scan_progress = i
            
#             # Actual scan logic
#             suspicious_processes = ["keylogger", "logkeys", "pykeylogger", "ahk"]
#             found_threats = False
            
#             for proc in psutil.process_iter(['name', 'pid', 'exe']):
#                 try:
#                     if any(susp_keyword in proc.info['name'].lower() for susp_keyword in suspicious_processes):
#                         print(f"\n[!] Suspicious Process: {proc.info['name']} (PID: {proc.pid})")
#                         found_threats = True
                    
#                     if platform.system() == "Windows" and "temp" in proc.info.get('exe', '').lower():
#                         print(f"\n[!] Suspicious Temp Execution: {proc.info['name']}")
#                         found_threats = True
#                 except:
#                     continue

#             if not found_threats:
#                 print("\n[+] No obvious threats detected")
            
#         finally:
#             self.scan_complete.set()
#             spinner_thread.join()
#             print("[+] System scan completed at 100%")

#     def network_monitor(self):
#         print("\n[+] Monitoring network connections...")
#         for conn in psutil.net_connections():
#             if conn.status == "ESTABLISHED" and conn.raddr:
#                 print(f"[→] {conn.laddr.ip}:{conn.laddr.port} → {conn.raddr.ip}:{conn.raddr.port} (PID: {conn.pid})")
#         print("[+] Network scan completed")

#     def check_updates(self):
#         try:
#             response = requests.get(CONFIG['UPDATE_URL'], timeout=5)
#             if response.status_code == 200:
#                 latest_version = response.json().get('tag_name', '').lstrip('v')
#                 if latest_version > CONFIG['CURRENT_VERSION']:
#                     return f"Update available: v{latest_version} (Current: v{CONFIG['CURRENT_VERSION']})\nDownload: {response.json().get('html_url', '')}"
#                 return "You're running the latest version"
#             return "Failed to check updates (API error)"
#         except Exception as e:
#             return f"Update check failed: {str(e)}"

#     def vt_check_file(self, file_path):
#         try:
#             file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
#             params = {'apikey': CONFIG['VT_API_KEY'], 'resource': file_hash}
#             response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
#             return response.json()
#         except Exception as e:
#             return {'error': str(e)}

#     def vt_scan_menu(self):
#         print("\n[VirusTotal Scan]")
#         file_path = input("Enter file path: ").strip()
#         if os.path.exists(file_path):
#             result = self.vt_check_file(file_path)
#             print(json.dumps(result, indent=2))
#         else:
#             print("[!] File not found")

#     def show_help(self):
#         print("""
#         DSTerminal Commands:
        
#         scan       - System threat scan (keyloggers/malware)
#         netmon     - Real-time network monitoring
#         harden     - Apply security configurations
#         vtscan     - Scan file with VirusTotal
#         update     - Check for DST updates
#         help       - Show this help
#         exit       - Exit terminal
#         """)

#     def run(self):
#         self.print_banner()
#         while True:
#             try:
#                 user_input = self.session.prompt('DST> ')
#                 self.handle_command(user_input.strip())
#             except KeyboardInterrupt:
#                 print("\n[*] Use 'exit' to quit")
#             except Exception as e:
#                 print(f"[!] Error: {str(e)}")

#     def handle_command(self, cmd):
#         if cmd == "scan":
#             self.scan_system()
#         elif cmd == "netmon":
#             self.network_monitor()
#         elif cmd == "update":
#             print(f"\n[+] {self.check_updates()}")
#         elif cmd == "vtscan":
#             self.vt_scan_menu()
#         elif cmd == "help":
#             self.show_help()
#         elif cmd == "exit":
#             sys.exit(0)
#         else:
#             os.system(cmd)

# if __name__ == "__main__":
#     terminal = SecurityTerminal()
#     terminal.run()


import os
import platform
import subprocess
import hashlib
import socket
import datetime
import shutil
import time
import json
import requests
import uuid
from cryptography.fernet import Fernet

class SecurityTerminal:
    def __init__(self):
        self.system = platform.system()
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def run(self):
        print("DSTerminal started. Type 'help' for commands.")
        while True:
            command = input("DS> ").strip().lower()
            if command == "exit":
                break
            elif hasattr(self, command):
                getattr(self, command)()
            else:
                print(f"Unknown command: {command}")

    def help(self):
        print("""
        Available Commands:
        scan           - Perform system scan
        port_scan      - Scan open ports
        netmon         - Monitor network traffic
        vtscan         - Scan with VirusTotal
        regmon         - Monitor registry changes
        exploitcheck   - Check for known vulnerabilities
        encrypt_file   - Encrypt a file
        decrypt_file   - Decrypt a file
        watch_folder   - Monitor file system changes
        hashcheck      - Check file integrity
        sysinfo        - Display system information
        traceroute     - Perform a traceroute
        macspoof       - Spoof MAC address
        dnssec         - Check DNSSEC config
        sqlmap         - Run SQL injection test
        kill_process   - Kill a process
        ransomware_monitor - Detect ransomware activity
        stego_detect   - Detect steganography in files
        ssl_cert_check - Verify SSL certificates
        tor_routing    - Check for Tor routing leaks
        exit           - Exit the tool
        """)

    def scan(self):
        print("[+] Performing system scan...")
        self.sysinfo()
        self.watch_folder(".")
        self.hashcheck()

    def port_scan(self, target="127.0.0.1"):
        print(f"[+] Scanning ports on {target}...")
        for port in range(1, 1025):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((target, port))
                if result == 0:
                    print(f"Port {port} is open")

    def netmon(self):
        print("[+] Monitoring network traffic...")
        os.system("netstat -tulnp" if self.system != "Windows" else "netstat -ano")

    def vtscan(self, file_path):
        print("[+] Scanning file with VirusTotal...")
        API_KEY = "your_virustotal_api_key"
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": API_KEY}
        files = {"file": open(file_path, "rb")}
        response = requests.post(url, files=files, headers=headers)
        print(response.json())

    def regmon(self):
        print("[!] Registry monitoring is Windows-specific and requires advanced setup.")

    def exploitcheck(self):
        print("[+] Checking for known exploits...")
        os.system("searchsploit firefox" if shutil.which("searchsploit") else "echo 'SearchSploit not installed'")

    def encrypt_file(self, filepath):
        print(f"[+] Encrypting file: {filepath}")
        with open(filepath, 'rb') as file:
            encrypted = self.cipher.encrypt(file.read())
        with open(filepath + '.enc', 'wb') as file:
            file.write(encrypted)
        print("[+] Encryption complete.")

    def decrypt_file(self, filepath):
        print(f"[+] Decrypting file: {filepath}")
        with open(filepath, 'rb') as file:
            decrypted = self.cipher.decrypt(file.read())
        with open(filepath.replace('.enc', ''), 'wb') as file:
            file.write(decrypted)
        print("[+] Decryption complete.")

    def watch_folder(self, folder):
        print(f"[+] Watching folder: {folder}")
        before = dict([(f, None) for f in os.listdir(folder)])
        time.sleep(5)
        after = dict([(f, None) for f in os.listdir(folder)])
        added = [f for f in after if f not in before]
        removed = [f for f in before if f not in after]
        if added: print("Added: ", added)
        if removed: print("Removed: ", removed)

    def hashcheck(self):
        print("[+] Checking hashes of files...")
        for filename in os.listdir('.'):
            if os.path.isfile(filename):
                with open(filename, 'rb') as f:
                    data = f.read()
                    print(f"SHA256 {filename}: {hashlib.sha256(data).hexdigest()}")

    def sysinfo(self):
        print("[+] System Information:")
        print(f"System: {platform.system()} {platform.release()}")
        print(f"Hostname: {socket.gethostname()}")
        print(f"IP Address: {socket.gethostbyname(socket.gethostname())}")

    def traceroute(self, host="8.8.8.8"):
        print(f"[+] Tracing route to {host}...")
        command = "traceroute" if self.system != "Windows" else "tracert"
        os.system(f"{command} {host}")

    def macspoof(self):
        print("[!] MAC spoofing requires elevated permissions and platform-specific tools.")

    def dnssec(self):
        print("[+] Checking DNSSEC...")
        os.system("dig +dnssec example.com" if self.system != "Windows" else "echo 'Use nslookup / dig manually'")

    def sqlmap(self):
        print("[+] Launching SQLMap...")
        os.system("sqlmap -h" if shutil.which("sqlmap") else "echo 'SQLMap not installed'")

    def kill_process(self):
        pid = input("Enter PID to kill: ")
        try:
            os.kill(int(pid), 9)
            print(f"[+] Killed process {pid}")
        except Exception as e:
            print(f"[!] Failed to kill process: {e}")

    def ransomware_monitor(self):
        print("[+] Simulating ransomware detection...")
        suspicious = [f for f in os.listdir('.') if f.endswith('.locked')]
        if suspicious:
            print("[!] Possible ransomware activity: ", suspicious)
        else:
            print("[+] No ransomware activity detected.")

    def stego_detect(self):
        print("[+] Placeholder for steganography detection.")

    def ssl_cert_check(self):
        print("[+] Placeholder for SSL cert verification.")

    def tor_routing(self):
        print("[+] Placeholder for Tor leak test.")

    def show_help(self):
        help_text = """
        DSTerminal Professional Commands:
        
        scan       - Comprehensive system scan
        netmon     - Real-time network monitoring
        harden     - System hardening toolkit
        vtscan     - VirusTotal file scanning
        regmon     - Windows registry monitor
        memdump    - Memory process analysis
        update     - Check for DST updates
        help       - Show this help
        exit       - Exit terminal
        
        Any system command also works
        """
        print(help_text)

    def exit_terminal(self):
        print("\n[*] Exiting Defensive Security Terminal")
        sys.exit(0)

    def print_banner(self):
        print(f"""
        ██████╗ ███████╗███████╗███████╗███╗   ██╗███████╗██╗  ██╗
        ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔════╝╚██╗██╔╝
        ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║█████╗   ╚███╔╝ 
        ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██╔══╝   ██╔██╗ 
        ██████╔╝██║     ██║     ███████╗██║ ╚████║███████╗██╔╝ ██╗
        ╚═════╝ ╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        
        Defensive Security Terminal v1.1 | {platform.system()} {platform.release()}
        Developed by: Spark Wilson Spink | © 2024| Powered by Stark Expo Tech Exchange
        Type 'help' for available commands
        """)

    def run(self):
        self.print_banner()
        while True:
            try:
                user_input = self.session.prompt('DFFENEX@DSTerminal --] ')
                self.run_command(user_input.strip())
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to quit")
            except EOFError:
                self.exit_terminal()


if __name__ == '__main__':
    terminal = SecurityTerminal()
    terminal.run()
