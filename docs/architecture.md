# System Architecture & Academic Design

SentinelAI is built as a modular, asynchronous, research-grade security solution. It consists of multiple modules working together to capture, analyze, and mitigate attacker interactions.

---

## Modular Subsystem Flowchart

```
+-------------------------------------------------------------+
|                      ATTACKER PROBES                        |
|   (SSH: 2222)   (HTTP: 8080)   (FTP: 2121)   (Telnet: 2323) |
+------------------------------------+------------------------+
                                     |
                                     v
+-------------------------------------------------------------+
|                 PROTOCOL EMULATION LAYERS                   |
|  * Paramiko SSH   * FastAPI HTTP   * Async Socket FTP/Telnet |
+------------------------------------+------------------------+
                                     |
                         [Registers connection]
                                     |
                                     v
+-------------------------------------------------------------+
|                    SESSION RECORDER CORE                    |
|  * Generates Session UUID    * Buffers inputs / credentials |
+------------------------------------+------------------------+
                                     v
+-------------------------------------------------------------+
|                 ADAPTIVE CONTROLLER ACTIONS                 |
|  * Progressive Tarpit (Network Delay Latencies)             |
|  * Dynamic decoy path generation (HTTP .env / PHP configs)  |
|  * Sandbox trapping / Auto-Authentication                   |
+----------------------+-----------------------------+--------+
                       |                             |
             [Analyzes behaviors]          [Writes quarantine]
                       |                             |
                       v                             v
+------------------------------+             +----------------+
|  BEHAVIORAL ATTACK ANALYZER  |             |  FILE ISOLATOR |
|  * Maps to MITRE ATT&CK codes|             |  * Quarantines |
|  * Tracks Kill Chain Stages  |             |  * Hashing     |
+----------------------+-------+             +-------+--------+
                       |                             |
                       +--------------+--------------+
                                      |
                                      v
+-------------------------------------------------------------+
|                AI THREAT INTELLIGENCE ENGINE                |
|  * Predicts attack class using Random Forest Classifier     |
|  * Features: Login count, Cmd parameters, Malware flag...  |
|  * Computes threat score (0-100) & Threat Level            |
|  * Generates Explainable AI (XAI) descriptions              |
+-------------------------------------+-----------------------+
                                      |
                           [Triggers Event State]
                                      |
                                      v
+-------------------------------------------------------------+
|                      ALERTING SERVICE                       |
|  * Telegram Bot Markdown Alerts  * SMTP TLS Admin Mails     |
+-------------------------------------+-----------------------+
                                      |
                              [Saves State]
                                      |
                                      v
+-------------------------------------------------------------+
|                    MONGODB STORAGE LAYER                    |
|  * sessions   * attack_logs   * system_config   * reports   |
+-------------------------------------+-----------------------+
                                      |
                             [Dashboard API]
                                      |
                                      v
+-------------------------------------------------------------+
|                 REACT ADMINISTRATIVE PANEL                  |
|  * Real-time metrics overview   * Interactive shell replay  |
+-------------------------------------------------------------+
```

---

## Module Specifications

### 1. Protocol Emulators
Unlike standard honeypots that forward requests to internal systems or rely on full virtual machines, SentinelAI implements lightweight emulators:
- **SSH**: Simulates Ubuntu 22.04 LTS banner. Intercepts passwords and provides interactive mock bash commands.
- **HTTP**: Emulates paths scanned by vulnerabilities engines (e.g. `/wp-admin`, `/phpMyAdmin`). Injects decoy credentials and databases on request.
- **FTP/Telnet**: Custom socket listeners processing low-level connection commands, allowing login captures and malware uploads.

### 2. Adaptive Tarpit & Trapping
- **Tarpit Latency**: Dynamic tarpitting adds network delay before socket writes if repeated credential errors from an IP are registered.
- **Credential Capture Sandbox**: If brute forcing exceeds 8 failures, the honeypot changes state to auto-accept *any* credentials, granting the scanner shell access to intercept post-compromise commands.
- **Decoys**: Directories scanned dynamically populate with fake configs containing decoy SQL schemas or AWS API key structures.

### 3. Machine Learning Classification
SentinelAI uses a Trained `RandomForestClassifier` to map connection parameters to a specific class. The feature matrix details:
- Connection density (events per unit duration)
- Ratio of unique login attributes (usernames vs passwords)
- Command length and occurrence of shell chaining parameters (`;`, `&&`, `|`)
- Malware flag

The **Explainable AI (XAI)** module interprets the tree features and outputs clear security suggestions to the admin.

### 4. MITRE ATT&CK Tactic Mapping
Commands run are matched dynamically against known indicators of compromise (IOCs) and mapped to ATT&CK ID lists:
- `whoami`, `id` -> Discovery (T1033)
- `wget`, `curl` -> Ingress Tool Transfer (T1105)
- `chmod` -> Permissions Modification (T1222)
- `rm` -> Indicator Removal (T1070)
- `cat /etc/passwd` -> Credential Dumping (T1003.008)
