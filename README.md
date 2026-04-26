# HisLiLogger
### Linux-based Typed Commands History Logger and Extractor Tool

> **CY-2002/3006 Digital Forensics — Semester Project**

---

## Tool Overview

**HisLiLogger** is a digital forensics tool for Linux that extracts, aggregates, and visualizes a user's command and browsing history from multiple sources. It presents findings in a clean GUI and exports results in forensics-ready `.txt` reports.

### What It Extracts

| Source | Details |
|---|---|
| Shell History | `.bash_history`, `.zsh_history`, `.sh_history`, `.history`, fish history |
| Recently Used Files | `.local/share/recently-used.xbel` (GNOME standard) |
| Firefox History | `places.sqlite` from all Firefox profiles |
| Chrome/Chromium/Brave | `History` SQLite databases |
| Keyword Dictionary | Built from all above sources — minimum 3 chars, no limit max |

---

## Dependencies and Prerequisites

- **OS:** Linux (Ubuntu 20.04+, Fedora, Debian, Arch — any modern distro)
- **Python:** 3.8 or higher

### Standard Library Only (no pip install needed)
All modules used are part of Python's standard library:
- `tkinter` — GUI
- `sqlite3` — Browser database reading
- `xml.etree.ElementTree` — XBEL file parsing
- `hashlib` — SHA-256 hashing (chain of custody)
- `threading` — Non-blocking extraction
- `collections`, `re`, `pathlib`, `shutil`, `tempfile`, `datetime`

> **Note:** On some minimal Ubuntu installs, tkinter may need to be installed:
> ```bash
> sudo apt install python3-tk
> ```

---

## Installation Instructions

```bash
# 1. Clone or copy the project folder
git clone https://github.com/yourgroup/HisLiLogger.git
cd HisLiLogger

# 2. Verify Python version (must be 3.8+)
python3 --version

# 3. Install tkinter if missing (Debian/Ubuntu only)
sudo apt install python3-tk

# 4. Make the script executable
chmod +x hislilogger.py

# 5. Run the tool
python3 hislilogger.py
```

---

## Execution Steps

### Running the GUI

```bash
python3 hislilogger.py
```

### Step-by-Step Usage

1. **Launch** — Run the command above. The GUI window opens.
2. **Set Target** — The "Target Home Dir" defaults to your home directory. Click **Browse** to select a different user's home (e.g., for forensic image analysis).
3. **Set Keyword Length** — Minimum keyword length (default: 3). Increase to filter noise.
4. **Click EXTRACT ALL** — Extraction runs in the background. A status bar shows progress.
5. **Review tabs:**
   - `Shell History` — All typed terminal commands
   - `Recently Used` — Files opened via GUI apps
   - `Browser History` — URLs from Firefox/Chrome/Chromium/Brave
   - `Keyword Dictionary` — Aggregated word frequency table
   - `Forensic Log` — Timestamped extraction log with file hashes
6. **Export:**
   - "Export Shell History (.txt)" — Shell commands only
   - "Export Browser History (.txt)" — Browser URLs only
   - "Export ALL (.txt)" — Everything in one file
   - "Export Keyword Dictionary" — Frequency-sorted word list
   - "Export Forensic Report" — Full report with SHA-256 hashes

---

## Platform Compatibility

| Platform | Supported |
|---|---|
| Ubuntu 20.04+ | ✅ |
| Debian 10+ | ✅ |
| Fedora 35+ | ✅ |
| Arch Linux | ✅ |
| Kali Linux | ✅ |
| macOS | ⚠️ Partial (no recently-used.xbel) |
| Windows | ❌ Not supported |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: tkinter` | Run `sudo apt install python3-tk` |
| Browser history not found | Browser may be open (SQLite lock). Close browser and retry. |
| Permission denied | Run with appropriate user permissions or `sudo` for another user's home |
| Firefox history empty | Check that `~/.mozilla/firefox/` exists and has profiles |
| XBEL file not found | File only exists on GNOME-based desktops |

---

## Project Structure

```
HisLiLogger/
├── hislilogger.py      # Main tool (GUI + extractors + keyword builder)
├── README.md           # This file
├── UserGuide.md        # Full user guide with screenshots
└── exports/            # Default export directory
```

---

## Authors
- Group members listed in User Guide (Work Division section)

## License
For academic/educational use only. Not for unauthorized access to user data.
