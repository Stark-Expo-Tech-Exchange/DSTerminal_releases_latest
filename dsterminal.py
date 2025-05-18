import os
import sys
import platform
import hashlib
import requests
import json
import psutil
import socket
from datetime import datetime
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from cryptography.fernet import Fernet

# Configuration
CONFIG = {
    'VT_API_KEY': 'YOUR_VIRUSTOTAL_API_KEY',
    'UPDATE_URL': 'https://api.github.com/repos/yourrepo/dsterminal/releases/latest',
    'LOG_FILE': 'secure_audit.log',
    'ENCRYPT_KEY': Fernet.generate_key().decode()  # In production, store securely
}

class SecurityTerminal:
    def __init__(self):
        self.session = PromptSession(
            history=FileHistory('.dst_history'),
            auto_suggest=AutoSuggestFromHistory(),
            completer=WordCompleter([
                'scan', 'netmon', 'harden', 'vtscan', 
                'regmon', 'memdump', 'update', 'help', 'exit'
            ]),
            bottom_toolbar=HTML('<b>DST</b> v1.1 | Mode: <style bg="ansired">{}</style>').format(
                'ADMIN' if self.is_admin() else 'USER')
        )
        self.cipher = Fernet(CONFIG['ENCRYPT_KEY'].encode())
        
    def is_admin(self):
        try:
            return os.getuid() == 0 if platform.system() != 'Windows' else None
        except:
            return False

    def log_activity(self, message):
        encrypted = self.cipher.encrypt(message.encode())
        with open(CONFIG['LOG_FILE'], 'ab') as f:
            f.write(encrypted + b'\n')

    def vt_check_file(self, file_path):
        try:
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            params = {'apikey': CONFIG['VT_API_KEY'], 'resource': file_hash}
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
            return response.json()
        except Exception as e:
            return {'error': str(e)}

    def scan_memory(self):
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            if proc.info['memory_percent'] > 30:  # Threshold
                suspicious.append(proc.info)
        return suspicious

    def monitor_registry(self):
        if platform.system() == 'Windows':
            import winreg
            keys_to_monitor = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SYSTEM\CurrentControlSet\Services"
            ]
            changes = []
            for key_path in keys_to_monitor:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    changes.append(f"Registry key accessed: {key_path}")
                except Exception as e:
                    changes.append(f"Registry error: {str(e)}")
            return changes
        return ["Registry monitoring available only on Windows"]

    def check_updates(self):
        try:
            response = requests.get(CONFIG['UPDATE_URL'])
            latest_ver = response.json().get('tag_name', '1.0')
            return f"Update available: {latest_ver}" if latest_ver != "1.1" else "You have the latest version"
        except:
            return "Failed to check updates"

    def run_command(self, cmd):
        commands = {
            'scan': lambda: self.scan_system(),
            'netmon': lambda: self.network_monitor(),
            'harden': lambda: self.harden_system(),
            'vtscan': lambda: self.vt_scan_menu(),
            'regmon': lambda: print(self.monitor_registry()),
            'memdump': lambda: print(self.scan_memory()),
            'update': lambda: print(self.check_updates()),
            'help': lambda: self.show_help(),
            'exit': lambda: self.exit_terminal()
        }
        
        if cmd.split()[0] in commands:
            self.log_activity(f"Command executed: {cmd}")
            commands[cmd.split()[0]]()
        else:
            os.system(cmd)

    def scan_system(self):
        print("\n[+] Scanning for keyloggers and malware...")
        suspicious_processes = ["keylogger", "logkeys", "pykeylogger", "ahk"]
        for proc in psutil.process_iter(['name']):
            if any(susp_keyword in proc.info['name'].lower() for susp_keyword in suspicious_processes):
                print(f"[!] Suspicious Process: {proc.info['name']} (PID: {proc.pid})")
    
        if platform.system() == "Windows":
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
                for i in range(0, winreg.QueryInfoKey(key)[1]):
                    name, value, _ = winreg.EnumValue(key, i)
                    if "keylog" in name.lower() or "logger" in value.lower():
                        print(f"[!] Suspicious Startup Entry: {name} -> {value}")
            except:
                pass
        print("[+] System scan completed")

    def network_monitor(self):
        print("\n[+] Monitoring network connections...")
        for conn in psutil.net_connections():
            if conn.status == "ESTABLISHED" and conn.raddr:
                print(f"[+] Connection: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
        print("[+] Network scan completed")

    def harden_system(self):
        print("\n[+] Applying basic system hardening...")
        if platform.system() == "Windows":
            os.system("powercfg -h off")
            os.system("bcdedit /set {current} nx AlwaysOn")
        else:
            os.system("sudo chmod 700 /etc/crontab")
        print("[+] Hardening completed")

    def vt_scan_menu(self):
        print("\n[VirusTotal Scan]")
        file_path = input("Enter file path: ").strip()
        if os.path.exists(file_path):
            result = self.vt_check_file(file_path)
            print(json.dumps(result, indent=2))
        else:
            print("[!] File not found")

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
                user_input = self.session.prompt('DST> ')
                self.run_command(user_input.strip())
            except KeyboardInterrupt:
                print("\n[*] Use 'exit' to quit")
            except EOFError:
                self.exit_terminal()

if __name__ == "__main__":
    terminal = SecurityTerminal()
    terminal.run()