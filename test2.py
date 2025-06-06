from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.align import Align
from threading import Thread
import time
import psutil
import platform

class SecurityTerminal:
    def __init__(self):
        self.scan_progress = 0
        self.console = Console()

    def scan_system(self):
        stages = [
            ("[cyan]Scanning Memory for anomalies...[/cyan]", "Memory Scan"),
            ("[yellow]Analyzing Active Processes...[/yellow]", "Process Scan"),
            ("[magenta]Inspecting Temporary & Hidden Files...[/magenta]", "Temp File Scan"),
            ("[blue]Reviewing Network Connections...[/blue]", "Network Scan"),
            ("[green]Checking Installed Applications...[/green]", "Software Audit"),
            ("[white]Verifying System Integrity...[/white]", "System Integrity"),
            ("[red]Reviewing User Accounts & Privileges...[/red]", "User Audit"),
            ("[bright_cyan]Assessing Firewall and Security Tools...[/bright_cyan]", "Security Configs"),
            ("[bright_magenta]Applying Heuristic & Behavioral Analysis...[/bright_magenta]", "Heuristics")
        ]

        def animated_progress():
            with Live(console=self.console, refresh_per_second=10, screen=True) as live:
                for stage_text, task_label in stages:
                    progress = Progress(
                        TextColumn(stage_text),
                        BarColumn(bar_width=None),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        expand=True,
                    )
                    task = progress.add_task(task_label, total=100)
                    start_time = time.time()
                    while not progress.finished:
                        elapsed = time.time() - start_time
                        percent = min(100, int((elapsed / 5) * 100))
                        progress.update(task, completed=percent)
                        panel = Panel(
                            Align.center(progress, vertical="middle"),
                            title="[bold white]System Scan[/bold white]",
                            border_style="bright_white",
                            padding=(1, 2),
                            width=70
                        )
                        live.update(panel)
                        time.sleep(0.1)

        animation_thread = Thread(target=animated_progress)
        animation_thread.start()
        animation_thread.join()

        # Simulated real scan - process detection
        suspicious_keywords = ["keylogger", "logkeys", "pykeylogger", "ahk", "injector"]
        found_threats = False

        for proc in psutil.process_iter(['name', 'pid', 'exe']):
            try:
                name = proc.info.get('name', '').lower()
                exe = (proc.info.get('exe') or '').lower()
                if any(kw in name for kw in suspicious_keywords):
                    self.console.print(f"\n[bold red][!] Suspicious Process:[/bold red] {proc.info['name']} (PID: {proc.pid})")
                    found_threats = True
                if platform.system() == "Windows" and "temp" in exe:
                    self.console.print(f"\n[bold yellow][!] Executable Running from Temp Directory:[/bold yellow] {proc.info['name']}")
                    found_threats = True
            except Exception:
                continue

        if not found_threats:
            self.console.print("\n[bold green][+] No obvious threats detected[/bold green]")


if __name__ == "__main__":
    term = SecurityTerminal()
    term.scan_system()
