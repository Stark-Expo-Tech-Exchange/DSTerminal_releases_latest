
📐 Defensive Security Terminal – Modular Architecture >>Arquitectura del Terminal de Seguridad

+-----------------------------------------------------------+
|                    DEFENSIVE SECURITY TERMINAL            |
|                       (DSTerminal CLI)                    |
+-----------------------------------------------------------+
|                                                           |
| 1. Monitoring Engine       |  Network Monitor  |  Log Analyzer  |
|---------------------------|-------------------|----------------|
| - Packet capture (tcpdump, Wireshark)                     |
| - Live log tailing (syslog, auth logs, app logs)          |
|                                                           |
| 2. Vulnerability Scanner   |  Port Scanner   |  Config Checker |
|---------------------------|------------------|----------------|
| - Nmap safe scan modes                                      |
| - OS/hardware CVE check                                     |
| - Misconfiguration detection                                |
|                                                           |
| 3. Incident Response       |  Kill Process   |  Quarantine Tool|
|---------------------------|------------------|----------------|
| - Auto-isolate suspicious device                          |
| - Stop malicious scripts                                   |
|                                                           |
| 4. Threat Intelligence     |  VirusTotal API |  IOC Matching   |
|---------------------------|------------------|----------------|
| - Domain/IP reputation lookup                             |
| - Local IOC database search                                |
|                                                           |
| 5. Security Hardening      |  Firewall Config|  Patch Checker  |
|---------------------------|------------------|----------------|
| - UFW/iptables scripts                                     |
| - Secure file permissions scanner                          |
|                                                           |
| 6. Automation & Scheduler  |  Cron Jobs      |  Email Alerts   |
|---------------------------|------------------|----------------|
| - Schedule vulnerability scans                            |
| - Alert SOC or admin on detection                          |
|                                                           |
| 7. Training Simulator      |  Simulated Attacks |  Quiz Mode    |
|---------------------------|------------------|----------------|
| - Generate fake logs, phishing emails                     |
| - Terminal-based training questions                        |
|                                                           |
+-----------------------------------------------------------+
|   Data Storage: JSON Logs | SQLite | Encrypted Vault       |
+-----------------------------------------------------------+
