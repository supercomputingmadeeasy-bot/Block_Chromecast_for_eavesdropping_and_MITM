# AI + Watchdog Cooperation — Full Technical Documentation

> How the rule-based monitors, the AI Analyser, and the hardware watchdog
> work **together** to detect, escalate, and respond to threats on the
> Raspberry Pi 4 gateway.

---

## 1 — The Big Picture

Two independently operating layers guard the gateway simultaneously.
They share data through the structured log, but they **never block each other**.

```mermaid
flowchart TD
    INTERNET["🌐 Internet / WAN  (eth0)"]
    LAN["🏠 LAN  10.42.0.0/24  (eth1 / wlan0)"]

    subgraph KERNEL["Linux Kernel — Netfilter"]
        IPT["iptables\nFORWARD / INPUT / NAT chains"]
        LOG_TARGET["LOG target → kernel ring buffer\n(FW-NULLSCAN, FW-SYNFLOOD, …)"]
    end

    subgraph WATCHDOG["pi_watchdog.py — Seven Concurrent Threads"]
        HW["🔧 HardwareWatchdog\n/dev/watchdog every 10 s"]
        ARP["🔍 ARPMonitor\n/proc/net/arp every 5 s"]
        KERN["📋 KernelLogMonitor\njournalctl -k (stream)"]
        AUTH["🔐 AuthLogMonitor\njournalctl -u sshd (stream)"]
        SVC["⚙️ ServiceMonitor\nsystemctl every 60 s"]
        EXP["⏱ ExpiryManager\nevery 5 min"]
        STAT["📊 StatusReporter\nevery 10 min"]
    end

    subgraph AI_LAYER["🤖 AIAnalyser Thread  (every 30 s)"]
        TAIL["tail -n 200 watchdog.log"]
        SCORE["Rule-based scoring\nTHREAT_SCORE_MAP per event type"]
        COORD["Coordination bonus\n+3 if same IP in ≥3 attack types"]
        LLM["Optional LLM\n(phi3:mini via ollama)\ncan only UPGRADE score"]
        LEVEL["Threat level\nNORMAL / SUSPICIOUS / CRITICAL / FATAL"]
    end

    subgraph RESPONSE["Response Layer"]
        BLOCKER["IPBlocker\niptables -I INPUT -s <ip> -j DROP\nblocklist.json  (24 h TTL)"]
        NOTIFY["NotificationManager\nwall + ai_alerts.json + FATAL_ALERT"]
        SHUTDOWN["EmergencyShutdown\nFORWARD=DROP, NAT flush,\nWAN interface DOWN"]
    end

    subgraph WEBUI["Web UI — ui_server.py :8080"]
        POLL["Browser polls\nai_alerts.json every 5 s"]
    end

    INTERNET --> IPT
    IPT --> LAN
    IPT --> LOG_TARGET

    LOG_TARGET -->|"kernel ring buffer"| KERN
    KERN -->|"threshold exceeded"| BLOCKER
    AUTH -->|"≥4 SSH fails / 120 s"| BLOCKER
    ARP -->|"MAC change detected"| NOTIFY

    KERN -->|"structured log line"| WATCHDOG
    AUTH -->|"structured log line"| WATCHDOG

    BLOCKER -->|"iptables DROP rule"| IPT
    EXP -->|"iptables -D (expiry)"| IPT

    HW -->|"sd_notify(WATCHDOG=1)"| SVC
    SVC -->|"systemctl is-active"| SVC

    WATCHDOG -->|"watchdog.log"| TAIL
    TAIL --> SCORE
    SCORE --> COORD
    COORD --> LLM
    LLM --> LEVEL

    LEVEL -->|"SUSPICIOUS / CRITICAL"| NOTIFY
    LEVEL -->|"FATAL"| NOTIFY
    LEVEL -->|"FATAL"| SHUTDOWN

    NOTIFY -->|"ai_alerts.json"| POLL
    NOTIFY -->|"wall broadcast"| POLL
```

---

## 2 — Two Distinct Defence Layers

| | Rule-based Monitors | AI Analyser |
|---|---|---|
| **Speed** | Real-time stream (milliseconds) | Cycle-based (every 30 s) |
| **Scope** | One attack type at a time | Cross-type correlation |
| **Trigger** | Threshold count per type | Cumulative threat score |
| **Output** | `iptables DROP` for offending IP | Threat level → notify / shutdown |
| **Can escalate to FATAL?** | No | Yes |
| **LLM involvement** | No | Optional (ollama) |

The **rule-based layer** is the first responder — it slams the door the moment
a scan or brute-force attack crosses a numeric threshold.

The **AI layer** is the investigator — it reads the compiled log, looks for
coordinated multi-vector attacks across all events, and can trigger an
**emergency lockdown** that no individual monitor can trigger on its own.

---

## 3 — Rule-Based Monitoring (Immediate Response)

### 3a — Kernel Log Monitor

```mermaid
sequenceDiagram
    participant K as Linux Kernel
    participant J as journalctl -k (stream)
    participant KLM as KernelLogMonitor
    participant IB as IPBlocker
    participant IPT as iptables

    loop Continuous stream
        K->>J: FW-NULLSCAN: SRC=1.2.3.4 DST=...
        J->>KLM: line
        KLM->>KLM: regex match → src_ip, event_type
        KLM->>KLM: sliding window (60 s)\ncount scan/flood events for src_ip
        alt scan_count ≥ 2
            KLM->>IB: block(src_ip, "port scan")
            IB->>IPT: iptables -I INPUT -s 1.2.3.4 -j DROP
            IB->>IB: blocklist.json  expiry=+24 h
        else flood_count ≥ 5
            KLM->>IB: block(src_ip, "DDoS flood")
            IB->>IPT: iptables -I INPUT -s 1.2.3.4 -j DROP
        end
        KLM->>KLM: log WARNING [ATTACK] eid=… to watchdog.log
    end
```

**Scan types detected:** `FW-NULLSCAN`, `FW-XMASSCAN`, `FW-FINSCAN`, `FW-SYNRST`, `FW-FRAGMENT`, `FW-INVALID`

**Flood types detected:** `FW-SYNFLOOD`, `FW-ICMPFLOOD`, `FW-UDPFLOOD`, `FW-CONNRATE`, `FW-CONNLIMIT`, `FW-FWDRATE`

---

### 3b — SSH Auth Monitor

```mermaid
sequenceDiagram
    participant S as sshd
    participant J as journalctl -u sshd (stream)
    participant ALM as AuthLogMonitor
    participant IB as IPBlocker
    participant IPT as iptables

    loop Continuous stream
        S->>J: Failed password for root from 5.6.7.8 port 54321
        J->>ALM: line
        ALM->>ALM: SSH_FAIL_RE match → src_ip, user, method
        ALM->>ALM: sliding deque (120 s window)\ncount failures for src_ip
        alt count ≥ 4
            ALM->>IB: block(src_ip, "SSH brute force")
            IB->>IPT: iptables -I INPUT -s 5.6.7.8 -j DROP
        end
        ALM->>ALM: log [SSH-FAIL] eid=… attempt=N/4
    end
```

---

### 3c — ARP Monitor (Cable MITM Detection)

```mermaid
sequenceDiagram
    participant P as /proc/net/arp
    participant AM as ARPMonitor (poll 5 s)
    participant NM as NotificationManager
    participant W as wall broadcast

    loop Every 5 seconds
        AM->>P: read ARP table
        P-->>AM: IP → MAC mappings
        AM->>AM: compare to known[] cache
        alt MAC changed for a known IP
            AM->>NM: notify(CRITICAL, "ARP-SPOOF", details)
            NM->>W: broadcast to all terminals
            NM->>NM: write ai_alerts.json
            Note over AM: Does NOT auto-block<br/>Gateway IP might be spoofed —<br/>physical inspection required
        else new IP seen
            AM->>AM: learn(IP → MAC)
        end
    end
```

---

## 4 — AI Analyser: The Threat Correlation Engine

The AI Analyser runs as a **separate daemon thread** with a 30-second polling cycle.
It does NOT block IPs directly — it observes the log, computes a holistic threat score,
and escalates to the notification / emergency shutdown pipeline.

```mermaid
flowchart TD
    A["⏱ Every 30 seconds\n_analyse() called"] --> B

    B["tail -n 200 watchdog.log"] --> C["Parse log lines\nLOG_LINE_RE regex\nextract: ts, level, cat, eid, src, type"]

    C --> D{"Any new events?\n(filter by eid\nagainst seen_eids set)"}
    D -->|"No new events"| Z["Sleep until next cycle"]
    D -->|"New events found"| E

    E["For each new event:\nip_scores[src_ip] += THREAT_SCORE_MAP[event_type]\nip_types[src_ip].add(event_type)"]

    E --> F{"Same IP in\n≥ 3 attack types?"}
    F -->|"Yes"| G["Coordination bonus\nip_scores[ip] += 3\nlog: coordinated multi-vector"]
    F -->|"No"| H
    G --> H

    H["max_score = max(ip_scores)\ntop_ip = highest-scoring IP\nlevel = score_to_level(max_score)"]

    H --> I{"level ≥ SUSPICIOUS\nAND llm_endpoint set?"}
    I -->|"Yes"| J["POST last 20 events\nto ollama /api/generate\nmodel: phi3:mini"]
    J --> K{"LLM response\nhigher than rule score?"}
    K -->|"Yes — upgrade only"| L["level = llm_level"]
    K -->|"No / error"| M
    L --> M
    I -->|"No"| M

    M["log [AI] Cycle — new_events=N score=X level=Y"]

    M --> N{level?}
    N -->|"NORMAL"| Z
    N -->|"SUSPICIOUS"| O["notify(SUSPICIOUS)\nwall + ai_alerts.json"]
    N -->|"CRITICAL"| P["notify(CRITICAL)\nwall + ai_alerts.json"]
    N -->|"FATAL"| Q["notify(FATAL)\nwall + ai_alerts.json\n+ FATAL_ALERT file"]
    Q --> R["EmergencyShutdown.execute()\nFORWARD=DROP\nNAT flush\nWAN interface DOWN\nwrite LOCKDOWN_ACTIVE"]

    O --> Z
    P --> Z
    R --> Z
```

---

## 5 — Threat Score Table

Every event type the watchdog logs is mapped to a numeric score.
The AI Analyser sums these scores per attacker IP in each 30-second cycle.

```mermaid
%%{init: {"pie": {"textPosition": 0.6}} }%%
pie title Threat Score Weights
    "ARP-SPOOF (8)" : 8
    "FW-SYNFLOOD (4)" : 4
    "FW-NULLSCAN / XMASSCAN / FINSCAN (3 each)" : 9
    "FW-ICMPFLOOD / UDPFLOOD / CONNRATE / FWDRATE (3 each)" : 12
    "FW-SYNRST / CONNLIMIT (2 each)" : 4
    "SSH-FAIL (2 per attempt)" : 2
    "FW-INVALID / FRAGMENT (1 each)" : 2
```

| Score Range | Threat Level | Action |
|---|---|---|
| 0 – 2 | `NORMAL` | Log only |
| 3 – 5 | `SUSPICIOUS` | Notify via wall + web UI |
| 6 – 9 | `CRITICAL` | Notify via wall + web UI |
| ≥ 10 | `FATAL` | Notify **+** Emergency lockdown |

**Coordination bonus:** if a single IP appears in 3 or more distinct attack
categories in the same cycle, `+3` is added to its score.
This catches sophisticated attackers who combine scans, floods, and SSH probing.

---

## 6 — Optional LLM Integration (ollama)

When `--llm-endpoint http://localhost:11434` is set, the AI Analyser sends the
last 20 log events to a local language model whenever the rule-based score
reaches SUSPICIOUS or above.

```mermaid
sequenceDiagram
    participant AI as AIAnalyser
    participant LLM as ollama (phi3:mini)
    participant N as NotificationManager

    AI->>AI: rule-based score → SUSPICIOUS (score=4)
    AI->>LLM: POST /api/generate\n{model: phi3:mini, prompt: "Analyse events…", stream: false}
    Note right of LLM: Model sees:\n[ATTACK] src=1.2.3.4 type=FW-NULLSCAN\n[SSH-FAIL] src=1.2.3.4 user=root\n[ATTACK] src=1.2.3.4 type=FW-SYNFLOOD
    LLM-->>AI: {"level": "CRITICAL", "reason": "coordinated scan + SSH + flood"}
    AI->>AI: CRITICAL > SUSPICIOUS → upgrade level
    Note over AI: LLM can ONLY upgrade, never downgrade
    AI->>N: notify(CRITICAL, summary, details)
```

**The LLM receives a strict prompt:**
```
You are a network security analyst on a Raspberry Pi gateway.
Analyse the log events below and classify the OVERALL threat level
as exactly one of: NORMAL, SUSPICIOUS, CRITICAL, FATAL.
Reply with valid JSON only: {"level": "CRITICAL", "reason": "..."}
```

If the endpoint is unreachable or returns garbage JSON, the system falls back
silently to the rule-based score — **no alert is missed**.

---

## 7 — Hardware Watchdog Integration

The software watchdog (Python) and the hardware watchdog (/dev/watchdog) operate
in a nested safety net.

```mermaid
flowchart LR
    subgraph PYTHON["Python Process"]
        HW["HardwareWatchdog\nthread"]
        PET["_pet() every 10 s\n→ write 0x01 to /dev/watchdog\n→ sd_notify(WATCHDOG=1)"]
        DISARM["stop() called on clean exit\n→ write 'V' magic close\n→ WDT disarmed — no reboot"]
    end

    subgraph KERNEL["Linux Kernel"]
        WDT["/dev/watchdog\nbcm2835_wdt driver\nhw_timeout = 15 s"]
        RESET["Hardware reset\n(BCM2711 WDT fires)"]
    end

    subgraph SYSTEMD["systemd"]
        SD["WatchdogSec=30s\nin .service file"]
        RESTART["Restart=on-failure\nRestartSec=5"]
    end

    HW --> PET
    PET -->|"write 0x01"| WDT
    PET -->|"sd_notify"| SD
    WDT -->|"countdown reset"| WDT
    WDT -->|"if not pet within 15 s\nprocess is hung/dead"| RESET
    SD -->|"if WATCHDOG signal stops\nprocess is hung"| RESTART
    DISARM -->|"clean shutdown"| WDT

    RESET -.->|"Pi reboots\nsystemd restarts watchdog\nautomatically"| PYTHON
```

**The nested safety net:**

1. Python `HardwareWatchdog` writes to `/dev/watchdog` every 10 s (< 15 s HW timeout)
2. `sd_notify("WATCHDOG=1")` satisfies systemd's `WatchdogSec=30s`
3. If **Python hangs** → hardware WDT fires at 15 s → Pi hard-reboots
4. If **Python crashes** → systemd restarts the service in 5 s
5. If **Python exits cleanly** → magic `'V'` written → WDT disarmed → no reboot

---

## 8 — Emergency Shutdown Sequence (FATAL Path)

This is the most drastic response, triggered **only** when the AI Analyser
determines the threat level reaches FATAL (score ≥ 10).

```mermaid
sequenceDiagram
    participant AI as AIAnalyser
    participant N as NotificationManager
    participant ES as EmergencyShutdown
    participant IPT as iptables / ip6tables
    participant SYS as sysctl / ip link
    participant F as Filesystem

    AI->>N: notify(FATAL, summary, details)
    N->>N: append to ai_alerts.json
    N->>N: write FATAL_ALERT file
    N->>N: wall broadcast to all terminals
    AI->>ES: execute(reason)

    ES->>IPT: iptables -P FORWARD DROP
    ES->>IPT: iptables -F FORWARD
    ES->>IPT: iptables -t nat -F POSTROUTING
    ES->>IPT: ip6tables -P FORWARD DROP
    ES->>IPT: ip6tables -F FORWARD
    ES->>SYS: sysctl -w net.ipv4.ip_forward=0
    ES->>SYS: sysctl -w net.ipv6.conf.all.forwarding=0
    ES->>SYS: ip link set eth0 down  [WAN disconnected]
    ES->>F: write LOCKDOWN_ACTIVE\n/opt/chromecast_blocker/logs/

    Note over ES: LAN SSH access preserved\n(INPUT chain NOT touched)\nAdmin can still log in and investigate

    Note over AI: To restore:\nsudo python3 pi_watchdog.py --clear-lockdown
```

---

## 9 — Notification Pipeline

Every alert generated by the AI Analyser travels through three simultaneous channels:

```mermaid
flowchart TD
    AI["AIAnalyser\n_escalate()"] --> NM["NotificationManager\n.notify(level, summary, details, eid)"]

    NM --> A["📺 wall broadcast\nAll logged-in terminal sessions\nsee the alert immediately"]

    NM --> B["📄 ai_alerts.json\n/opt/chromecast_blocker/logs/\nLast 200 alerts stored\nMax size ring-buffer"]

    NM --> C{"level == FATAL?"}
    C -->|"Yes"| D["⚡ FATAL_ALERT file\n/opt/chromecast_blocker/logs/\nPersists across reboots\nTimestamp + eid + reason"]

    B --> E["ui_server.py\nGET /api/alerts\nBrowser polls every 5 s"]

    E --> F["🌐 Web UI Dashboard\n:8080\nRed alert bar"]
```

---

## 10 — Full Thread Map (pi_watchdog.py)

```mermaid
gantt
    title Polling intervals of all watchdog threads (not to scale)
    dateFormat X
    axisFormat %s s

    section HardwareWatchdog
    pet /dev/watchdog          : 0, 10
    pet /dev/watchdog          : 10, 20
    pet /dev/watchdog          : 20, 30

    section ARPMonitor
    poll /proc/net/arp         : 0, 5
    poll /proc/net/arp         : 5, 10
    poll /proc/net/arp         : 10, 15
    poll /proc/net/arp         : 15, 20
    poll /proc/net/arp         : 20, 25
    poll /proc/net/arp         : 25, 30

    section KernelLogMonitor
    stream (continuous)        : 0, 30

    section AuthLogMonitor
    stream (continuous)        : 0, 30

    section AIAnalyser
    analysis cycle             : 0, 30

    section ServiceMonitor
    systemctl is-active        : 0, 30

    section ExpiryManager
    expire blocks (300 s)      : milestone, 0, 0

    section StatusReporter
    log status (600 s)         : milestone, 0, 0
```

---

## 11 — Data Flow: From Attack to Block

This is the complete end-to-end journey of a typical port scan attack:

```mermaid
flowchart TD
    A["🔴 Attacker SYN-scans\nthe gateway from\n203.0.113.42"] 

    A --> B["Linux kernel Netfilter\nmatches iptables rule:\n-m state --state NEW -j LOG\n--log-prefix 'FW-NULLSCAN: '"]

    B --> C["Kernel log ring buffer\n(dmesg)"]

    C --> D["journalctl -k stream\nKernelLogMonitor reads line"]

    D --> E["FW_RE regex match:\nevent_type = FW-NULLSCAN\nsrc_ip = 203.0.113.42"]

    E --> F["Sliding window counter\n203.0.113.42 → deque\n[NULLSCAN@T+0, NULLSCAN@T+1]"]

    F --> G{"scan_count ≥ 2?"}

    G -->|"Yes (2 events in 60 s)"| H["IPBlocker.block(ip, reason)\n▸ iptables -I INPUT -s 203.0.113.42 -j DROP\n▸ blocklist.json updated\n▸ log [BLOCKED] eid=a1b2c3d4"]

    G -->|"Not yet"| I["log [ATTACK] eid=… to watchdog.log\nwait for next event"]

    I --> J["⏱ 30 s later:\nAIAnalyser._analyse()"]

    J --> K["Parse watchdog.log\nnew event: type=FW-NULLSCAN src=203.0.113.42"]

    K --> L["ip_scores[203.0.113.42] += 3\n(NULLSCAN weight)"]

    L --> M["score=3 → SUSPICIOUS"]

    M --> N["NotificationManager.notify(SUSPICIOUS)\nwall + ai_alerts.json"]

    H --> O["✅ All further packets\nfrom 203.0.113.42\nDROPPED at kernel level\nfor 24 hours"]
```

---

## 12 — Multi-Vector Attack: AI Coordination Detection

This scenario shows **why the AI layer exists** — a sophisticated attacker
using multiple techniques simultaneously that no single monitor would escalate alone:

```mermaid
flowchart TD
    ATK["🔴 Attacker\n198.51.100.99"]

    ATK --> S1["Port scan\nFW-NULLSCAN × 2\n→ KernelLogMonitor\n→ IPBlocker.block() (DROP)"]
    ATK --> S2["SSH brute force\n4 failures\n→ AuthLogMonitor\n→ IPBlocker.block() (already blocked)"]
    ATK --> S3["SYN flood\nFW-SYNFLOOD × 6\n→ KernelLogMonitor\n→ (already blocked)"]

    S1 --> LOG["watchdog.log\n[ATTACK] type=FW-NULLSCAN src=198.51.100.99\n[SSH-FAIL] src=198.51.100.99 attempt=4/4\n[ATTACK] type=FW-SYNFLOOD src=198.51.100.99"]

    LOG --> AI["🤖 AIAnalyser (30 s cycle)"]

    AI --> SCORE["Scoring:\nFW-NULLSCAN = 3\nSSH-FAIL × 4 = 8\nFW-SYNFLOOD = 4\n──────────\nBase = 15"]

    SCORE --> COORD["Coordination check:\nNULLSCAN, SSH-FAIL, SYNFLOOD\n= 3 distinct types\n→ +3 coordination bonus"]

    COORD --> TOTAL["Total score = 18\n≥ 10 → FATAL"]

    TOTAL --> LLM["LLM (if enabled):\n'ARP spoof + port scan + SSH brute\nforce = FATAL'\n→ confirms FATAL"]

    TOTAL --> ALERT["NotificationManager\nlevel=FATAL\nwall + ai_alerts.json\nFATAL_ALERT file"]

    ALERT --> SHUTDOWN["EmergencyShutdown\n▸ FORWARD=DROP\n▸ NAT flushed\n▸ eth0 DOWN\n▸ LOCKDOWN_ACTIVE written"]
```

In this scenario:
- The **rule-based monitors** correctly block the IP immediately
- The **AI layer** recognises the coordinated nature (3 attack vectors, score 18) and **escalates to FATAL**
- The gateway **disconnects from the internet entirely** to protect all LAN clients

---

## 13 — Service Health Self-Monitoring

```mermaid
flowchart LR
    SM["ServiceMonitor\npoll every 60 s"]

    SM -->|"systemctl is-active"| S1["chromecast-blocker"]
    SM -->|"systemctl is-active"| S2["chromecast-ui"]
    SM -->|"systemctl is-active"| S3["fail2ban"]
    SM -->|"systemctl is-active"| S4["dnsmasq"]
    SM -->|"systemctl is-active"| S5["arpwatch"]
    SM -->|"systemctl is-active"| S6["arpwatch-lan"]

    S1 --> CHK{"State changed\nfrom last poll?"}
    S2 --> CHK
    S3 --> CHK
    S4 --> CHK
    S5 --> CHK
    S6 --> CHK

    CHK -->|"active → failed"| ERR["log ERROR:\n[Service] <name> changed state:\nactive → failed"]
    CHK -->|"failed → active"| REC["log INFO:\n[Service] <name> recovered"]
    CHK -->|"no change"| OK["(silent)"]
```

---

## 14 — Block Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Monitoring : watchdog starts\nblocklist.json loaded

    Monitoring --> Blocked : threshold exceeded\n(scan/flood/SSH/AI FATAL)

    Blocked --> Blocked : new packets DROP'd\nby iptables rule

    Blocked --> Expired : ExpiryManager\n(every 5 min)\nexpiry_timestamp ≤ now()

    Expired --> Monitoring : iptables -D rule removed\nblocklist.json updated\nlog [Unblocked]

    Blocked --> Renewed : same IP triggers\nanother violation\nexpiry timestamp reset

    Renewed --> Blocked
```

**Block TTL:** 24 hours by default (`--block-expire 86400`).
Blocks survive restarts (persisted to `blocklist.json`).

---

## 15 — Lockdown Recovery Procedure

If a FATAL threat triggers `EmergencyShutdown`, the Pi disconnects from the internet.
To restore:

```mermaid
flowchart TD
    A["🔒 LOCKDOWN_ACTIVE detected\nWAN interface down\nForwarding disabled"] 

    A --> B["Admin connects via LAN\n(INPUT chain intact)\nSSH to 10.42.0.1"]

    B --> C["Investigate:\npython3 trace_intruder.py --since 1h\ncat logs/intrusions.log\ncat logs/FATAL_ALERT"]

    C --> D{"Threat resolved?"}

    D -->|"No"| E["Keep lockdown\nNotify ISP / authorities\nPhysical inspection"]

    D -->|"Yes"| F["sudo python3 pi_watchdog.py --clear-lockdown"]

    F --> G["EmergencyShutdown.clear()\n▸ FORWARD policy → ACCEPT\n▸ ip_forward = 1\n▸ WAN interface UP\n▸ LOCKDOWN_ACTIVE deleted"]

    G --> H["Re-enable NAT manually\niptables -t nat -A POSTROUTING\n-o eth0 -j MASQUERADE"]

    H --> I["✅ Gateway restored\nMonitoring continues"]
```

---

## Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DEFENCE IN DEPTH                                │
│                                                                     │
│  Layer 1 (instant):   iptables rules (set by chromecast_blocker)   │
│  ─ DROP packets from known bad IPs / ports / protocols             │
│                                                                     │
│  Layer 2 (real-time): Rule-based monitors (KernelLog, AuthLog, ARP)│
│  ─ Count events per IP in a sliding window                         │
│  ─ Block the IP in iptables the moment threshold is crossed        │
│                                                                     │
│  Layer 3 (30 s):      AI Analyser                                  │
│  ─ Reads compiled log, scores events, detects coordinated attacks  │
│  ─ Optional LLM upgrade (phi3:mini via ollama)                     │
│  ─ Escalates to FATAL → EmergencyShutdown (WAN disconnect)        │
│                                                                     │
│  Layer 4 (15 s / HW): Hardware Watchdog (/dev/watchdog)           │
│  ─ If the Python process hangs → Pi hard-reboots automatically     │
│                                                                     │
│  All four layers operate concurrently in separate threads.         │
│  No single point of failure. No single decision-maker.             │
└─────────────────────────────────────────────────────────────────────┘
```
