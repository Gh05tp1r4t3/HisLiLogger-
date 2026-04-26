#!/usr/bin/env python3
"""
HisLiLogger v2.0 - Linux-based Typed Commands History Logger and Extractor Tool
CY-2002/3006 Digital Forensics Semester Project

STANDARD EXTRACTION:
  - Shell histories (.bash_history, .zsh_history, .sh_history, fish history)
  - Recently used files (.local/share/recently-used.xbel)
  - Browser histories (Firefox, Chrome, Chromium, Brave)
  - Keyword dictionary builder

ADVANCED FORENSIC MODULES (deleted/hidden artifact recovery):
  - [ADV-1] Deleted History Recovery via /proc/<pid>/fd  (live deleted file detection)
  - [ADV-2] SQLite Freelist Recovery  (deleted browser/Firefox rows from DB free pages)
  - [ADV-3] Thumbnail Cache Forensics  (~/.cache/thumbnails/ — persists after file deletion)
  - [ADV-4] Journal & Swap Carving    (journalctl session logs + /proc/swaps string carving)
"""

import os
import sys
import re
import json
import struct
import shutil
import sqlite3
import tempfile
import hashlib
import datetime
import subprocess
import xml.etree.ElementTree as ET
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from collections import Counter
import threading


# ═══════════════════════════════════════════════════════════════
#  BASE CLASS
# ═══════════════════════════════════════════════════════════════

class ForensicExtractor:
    def __init__(self, home_dir: str):
        self.home_dir = Path(home_dir)
        self.results = []
        self.errors = []

    def extract(self):
        raise NotImplementedError

    def file_hash(self, filepath: str) -> str:
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return "N/A"


# ═══════════════════════════════════════════════════════════════
#  STANDARD EXTRACTORS
# ═══════════════════════════════════════════════════════════════

class ShellHistoryExtractor(ForensicExtractor):
    HISTORY_FILES = [
        ".bash_history", ".zsh_history", ".sh_history", ".history",
        ".local/share/fish/fish_history", ".config/fish/fish_history",
    ]

    def extract(self):
        entries = []
        for rel_path in self.HISTORY_FILES:
            full_path = self.home_dir / rel_path
            if not full_path.exists():
                continue
            file_hash = self.file_hash(str(full_path))
            try:
                lines = open(full_path, "r", errors="replace").readlines()
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("- cmd:"):
                        line = line[6:].strip()
                    entries.append({
                        "source": str(full_path), "source_type": "Shell History",
                        "shell": rel_path, "line_no": i, "command": line,
                        "file_hash": file_hash,
                        "extracted_at": datetime.datetime.now().isoformat(),
                    })
            except Exception as e:
                self.errors.append(f"Shell read error ({rel_path}): {e}")
        self.results = entries
        return entries


class RecentlyUsedExtractor(ForensicExtractor):
    def extract(self):
        entries = []
        xbel_path = self.home_dir / ".local/share/recently-used.xbel"
        if not xbel_path.exists():
            self.errors.append("recently-used.xbel not found.")
            return entries
        file_hash = self.file_hash(str(xbel_path))
        try:
            tree = ET.parse(str(xbel_path))
            root = tree.getroot()
            for bookmark in root.iter():
                if not bookmark.tag.endswith("bookmark"):
                    continue
                href = bookmark.get("href", "")
                visited = bookmark.get("visited", "")
                mime = ""
                for child in bookmark.iter():
                    if child.tag.endswith("mime-type"):
                        mime = child.get("type", "")
                entries.append({
                    "source": str(xbel_path), "source_type": "Recently Used Files",
                    "file_uri": href,
                    "filename": href.split("/")[-1] if "/" in href else href,
                    "visited": visited, "modified": bookmark.get("modified", ""),
                    "mime_type": mime, "file_hash": file_hash,
                    "extracted_at": datetime.datetime.now().isoformat(),
                })
        except Exception as e:
            self.errors.append(f"XBEL parse error: {e}")
        self.results = entries
        return entries


class BrowserHistoryExtractor(ForensicExtractor):
    # Firefox-based browsers: (profile_base_dir, display_name)
    FIREFOX_BASED = [
        (".mozilla/firefox",                            "Firefox"),
        (".librewolf",                                  "LibreWolf"),
        (".waterfox",                                   "Waterfox"),
        (".floorp",                                     "Floorp"),
        (".zen-browser",                                "Zen Browser"),
    ]

    # Chromium-based browsers: (relative_history_path, display_name)
    # Each entry may include multiple profile patterns (Default, Profile 1, etc.)
    CHROMIUM_BASED = [
        (".config/google-chrome",                       "Google Chrome"),
        (".config/chromium",                            "Chromium"),
        (".config/BraveSoftware/Brave-Browser",         "Brave"),
        (".config/microsoft-edge",                      "Microsoft Edge"),
        (".config/opera",                               "Opera"),
        (".config/vivaldi",                             "Vivaldi"),
        (".config/thorium",                             "Thorium"),
        (".config/ungoogled-chromium",                  "Ungoogled Chromium"),
    ]

    def extract(self):
        self.results = self._extract_firefox_based() + self._extract_chromium_based()
        return self.results

    def _extract_firefox_based(self):
        entries = []
        for base_rel, browser_name in self.FIREFOX_BASED:
            ff_dir = self.home_dir / base_rel
            if not ff_dir.exists():
                continue
            for profile in ff_dir.iterdir():
                db_path = profile / "places.sqlite"
                if not db_path.exists():
                    continue
                fh = self.file_hash(str(db_path))
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
                tmp = tmp_file.name
                tmp_file.close()
                shutil.copy2(str(db_path), tmp)
                try:
                    conn = sqlite3.connect(tmp)
                    conn.row_factory = sqlite3.Row
                    for row in conn.execute(
                        "SELECT url,title,visit_count,last_visit_date FROM moz_places "
                        "WHERE visit_count>0 ORDER BY last_visit_date DESC LIMIT 500"
                    ):
                        vt = ""
                        if row["last_visit_date"]:
                            try:
                                vt = (datetime.datetime(1970, 1, 1) +
                                      datetime.timedelta(microseconds=int(row["last_visit_date"]))
                                      ).strftime("%Y-%m-%d %H:%M:%S")
                            except Exception:
                                vt = str(row["last_visit_date"])
                        entries.append({
                            "source": str(db_path),
                            "source_type": f"{browser_name} History",
                            "profile": profile.name,
                            "url": row["url"],
                            "title": row["title"] or "",
                            "visit_count": row["visit_count"],
                            "last_visit": vt,
                            "file_hash": fh,
                            "extracted_at": datetime.datetime.now().isoformat(),
                        })
                    conn.close()
                except Exception as e:
                    self.errors.append(f"{browser_name} error ({profile.name}): {e}")
                finally:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
        return entries

    def _extract_chromium_based(self):
        entries = []
        for base_rel, browser_name in self.CHROMIUM_BASED:
            base_dir = self.home_dir / base_rel
            if not base_dir.exists():
                continue
            # Collect all profile directories (Default, Profile 1, Profile 2, ...)
            profile_dirs = []
            default_db = base_dir / "Default" / "History"
            if default_db.exists():
                profile_dirs.append((base_dir / "Default", "Default"))
            try:
                for item in base_dir.iterdir():
                    if item.is_dir() and item.name.startswith("Profile "):
                        db = item / "History"
                        if db.exists():
                            profile_dirs.append((item, item.name))
            except (PermissionError, OSError):
                pass

            for profile_dir, profile_name in profile_dirs:
                db_path = profile_dir / "History"
                if not db_path.exists():
                    continue
                fh = self.file_hash(str(db_path))
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
                tmp = tmp_file.name
                tmp_file.close()
                shutil.copy2(str(db_path), tmp)
                try:
                    conn = sqlite3.connect(tmp)
                    conn.row_factory = sqlite3.Row
                    for row in conn.execute(
                        "SELECT url,title,visit_count,last_visit_time FROM urls "
                        "ORDER BY last_visit_time DESC LIMIT 500"
                    ):
                        vt = ""
                        if row["last_visit_time"]:
                            try:
                                # Chromium epoch: microseconds since 1601-01-01
                                vt = (datetime.datetime(1601, 1, 1) +
                                      datetime.timedelta(microseconds=int(row["last_visit_time"]))
                                      ).strftime("%Y-%m-%d %H:%M:%S")
                            except Exception:
                                vt = str(row["last_visit_time"])
                        entries.append({
                            "source": str(db_path),
                            "source_type": f"{browser_name} History",
                            "profile": profile_name,
                            "url": row["url"],
                            "title": row["title"] or "",
                            "visit_count": row["visit_count"],
                            "last_visit": vt,
                            "file_hash": fh,
                            "extracted_at": datetime.datetime.now().isoformat(),
                        })
                    conn.close()
                except Exception as e:
                    self.errors.append(f"{browser_name} ({profile_name}) error: {e}")
                finally:
                    try:
                        os.unlink(tmp)
                    except Exception:
                        pass
        return entries


# ═══════════════════════════════════════════════════════════════
#  ADVANCED FORENSIC MODULE 1 — /proc/<pid>/fd DELETED FILE RECOVERY
# ═══════════════════════════════════════════════════════════════

class ProcFdDeletedHistoryExtractor(ForensicExtractor):
    """
    Scans /proc/<pid>/fd for file descriptors pointing to deleted history files.
    On Linux, when a process (e.g. bash) still has a history file open but it has
    been deleted from disk, the FD remains accessible at /proc/<pid>/fd/<n>
    and can be read to recover the deleted content.
    """

    HISTORY_NAMES = {".bash_history", ".zsh_history", ".sh_history", ".history",
                     "fish_history", "bash_history"}

    def extract(self):
        entries = []
        proc_path = Path("/proc")
        if not proc_path.exists():
            self.errors.append("/proc not available on this system.")
            return entries

        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        link_target = os.readlink(str(fd))
                    except (OSError, PermissionError):
                        continue

                    # Deleted files appear as "/path/to/file (deleted)"
                    is_deleted = "(deleted)" in link_target
                    basename = link_target.split("/")[-1].replace(" (deleted)", "").strip()

                    if basename not in self.HISTORY_NAMES:
                        continue

                    status = "DELETED (recovered via /proc)" if is_deleted else "LIVE (open fd)"

                    # Read the file content through the fd
                    try:
                        content = open(str(fd), "r", errors="replace").read()
                        commands = [
                            l.strip() for l in content.splitlines()
                            if l.strip() and not l.startswith("#")
                        ]
                        for i, cmd in enumerate(commands, 1):
                            if cmd.startswith("- cmd:"):
                                cmd = cmd[6:].strip()
                            entries.append({
                                "source": link_target,
                                "source_type": "Proc FD Recovery",
                                "pid": pid_dir.name,
                                "fd": fd.name,
                                "file": basename,
                                "status": status,
                                "line_no": i,
                                "command": cmd,
                                "extracted_at": datetime.datetime.now().isoformat(),
                            })
                    except (PermissionError, OSError):
                        # Can't read content, but still record the finding
                        entries.append({
                            "source": link_target,
                            "source_type": "Proc FD Recovery",
                            "pid": pid_dir.name,
                            "fd": fd.name,
                            "file": basename,
                            "status": status + " [permission denied — file exists]",
                            "line_no": 0,
                            "command": "[content unreadable — permission denied]",
                            "extracted_at": datetime.datetime.now().isoformat(),
                        })
            except (PermissionError, OSError):
                continue

        if not entries:
            entries.append({
                "source": "/proc/<pid>/fd", "source_type": "Proc FD Recovery",
                "pid": "N/A", "fd": "N/A", "file": "N/A",
                "status": "No deleted history FDs found (shells may have exited or files not deleted)",
                "line_no": 0, "command": "",
                "extracted_at": datetime.datetime.now().isoformat(),
            })

        self.results = entries
        return entries


# ═══════════════════════════════════════════════════════════════
#  ADVANCED FORENSIC MODULE 2 — SQLITE FREELIST PAGE RECOVERY
# ═══════════════════════════════════════════════════════════════

class SQLiteFreelistRecovery(ForensicExtractor):
    """
    Recovers deleted records from SQLite database free pages.

    When SQLite deletes a row, it marks the page as 'free' but does NOT zero
    the data. The old row data remains in the freelist pages until overwritten.
    This module reads the raw binary of the DB file, parses freelist pages,
    and carves out URL-like and command-like strings from deleted pages.

    Technique used in real forensic tools (e.g. SQLite Forensic Explorer,
    Oxygen Forensic Detective).
    """

    # SQLite page header constants
    SQLITE_HEADER_MAGIC = b"SQLite format 3\x00"
    PAGE_SIZE_OFFSET = 16
    FREELIST_HEAD_OFFSET = 32
    FREELIST_COUNT_OFFSET = 36

    # Patterns to carve from raw page data
    URL_RE = re.compile(
        rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,300}"
    )
    CMD_RE = re.compile(
        rb"(?:sudo|apt|git|ssh|scp|wget|curl|rm |mv |cp |cat |ls |cd |nano |vim |python|bash|sh |chmod|chown|grep|find|netcat|nc |nmap|ping|ifconfig|ip addr)[^\x00\n\r]{3,120}"
    )

    def extract(self):
        entries = []
        targets = self._find_db_files()

        for db_path in targets:
            fh = self.file_hash(str(db_path))
            recovered = self._carve_db(db_path)
            for rec in recovered:
                rec["source"] = str(db_path)
                rec["file_hash"] = fh
                rec["extracted_at"] = datetime.datetime.now().isoformat()
                entries.append(rec)

        if not entries:
            entries.append({
                "source": "N/A", "source_type": "SQLite Freelist Recovery",
                "db_name": "N/A", "record_type": "INFO",
                "recovered_data": "No deleted records found in freelist pages.",
                "page_no": 0, "offset": 0,
                "file_hash": "N/A",
                "extracted_at": datetime.datetime.now().isoformat(),
            })

        self.results = entries
        return entries

    def _find_db_files(self):
        paths = []
        # Firefox-based browsers
        firefox_bases = [
            ".mozilla/firefox", ".librewolf", ".waterfox", ".floorp", ".zen-browser",
        ]
        for base_rel in firefox_bases:
            ff_base = self.home_dir / base_rel
            if not ff_base.exists():
                continue
            for profile in ff_base.iterdir():
                for db in ["places.sqlite", "formhistory.sqlite", "downloads.sqlite"]:
                    p = profile / db
                    if p.exists():
                        paths.append(p)
        # Chromium-based browsers — scan Default + numbered profiles
        chromium_bases = [
            ".config/google-chrome",
            ".config/chromium",
            ".config/BraveSoftware/Brave-Browser",
            ".config/microsoft-edge",
            ".config/opera",
            ".config/vivaldi",
            ".config/thorium",
            ".config/ungoogled-chromium",
        ]
        for base_rel in chromium_bases:
            base_dir = self.home_dir / base_rel
            if not base_dir.exists():
                continue
            for profile_name in ["Default"] + [f"Profile {i}" for i in range(1, 6)]:
                p = base_dir / profile_name / "History"
                if p.exists():
                    paths.append(p)
        return paths

    def _carve_db(self, db_path: Path) -> list:
        entries = []
        db_name = db_path.name
        try:
            with open(db_path, "rb") as f:
                raw = f.read()
        except (PermissionError, OSError) as e:
            self.errors.append(f"Cannot read {db_path}: {e}")
            return entries

        # Validate SQLite magic
        if not raw.startswith(self.SQLITE_HEADER_MAGIC):
            return entries

        # Read page size from header
        try:
            page_size = struct.unpack(">H", raw[16:18])[0]
            if page_size == 1:
                page_size = 65536
            if page_size < 512:
                return entries
        except Exception:
            return entries

        # Read freelist trunk page number and count
        try:
            freelist_head = struct.unpack(">I", raw[32:36])[0]
            freelist_count = struct.unpack(">I", raw[36:40])[0]
        except Exception:
            return entries

        if freelist_count == 0 or freelist_head == 0:
            # No freelist pages — try carving entire file for deleted strings
            entries += self._carve_raw(raw, db_name, -1)
            return entries

        # Walk freelist trunk pages
        visited_pages = set()
        trunk_page = freelist_head
        while trunk_page > 0 and trunk_page not in visited_pages:
            visited_pages.add(trunk_page)
            page_offset = (trunk_page - 1) * page_size
            if page_offset + page_size > len(raw):
                break
            page_data = raw[page_offset: page_offset + page_size]

            # Carve strings from this freelist page
            entries += self._carve_raw(page_data, db_name, trunk_page)

            # Next trunk page (first 4 bytes of the trunk page)
            try:
                trunk_page = struct.unpack(">I", page_data[0:4])[0]
                leaf_count = struct.unpack(">I", page_data[4:8])[0]
                # Walk leaf pages referenced by this trunk
                for i in range(leaf_count):
                    leaf_page = struct.unpack(">I", page_data[8 + i*4: 12 + i*4])[0]
                    leaf_offset = (leaf_page - 1) * page_size
                    if leaf_offset + page_size <= len(raw):
                        leaf_data = raw[leaf_offset: leaf_offset + page_size]
                        entries += self._carve_raw(leaf_data, db_name, leaf_page)
            except Exception:
                break

        return entries

    def _carve_raw(self, data: bytes, db_name: str, page_no: int) -> list:
        found = []
        # Carve URLs
        for m in self.URL_RE.finditer(data):
            try:
                text = m.group(0).decode("utf-8", errors="replace").strip()
                found.append({
                    "source_type": "SQLite Freelist Recovery",
                    "db_name": db_name,
                    "record_type": "DELETED URL",
                    "recovered_data": text,
                    "page_no": page_no,
                    "offset": m.start(),
                })
            except Exception:
                pass
        # Carve shell commands
        for m in self.CMD_RE.finditer(data):
            try:
                text = m.group(0).decode("utf-8", errors="replace").strip()
                # Filter out garbage
                if text.isprintable() and len(text) > 5:
                    found.append({
                        "source_type": "SQLite Freelist Recovery",
                        "db_name": db_name,
                        "record_type": "DELETED CMD",
                        "recovered_data": text,
                        "page_no": page_no,
                        "offset": m.start(),
                    })
            except Exception:
                pass
        return found


# ═══════════════════════════════════════════════════════════════
#  ADVANCED FORENSIC MODULE 3 — THUMBNAIL CACHE FORENSICS
# ═══════════════════════════════════════════════════════════════

class ThumbnailCacheExtractor(ForensicExtractor):
    """
    Extracts forensic artifacts from GNOME/KDE thumbnail caches.

    Even after a file is deleted, its thumbnail (with the original file path
    embedded in PNG metadata) often remains in ~/.cache/thumbnails/.
    This is a well-known forensic artifact for proving a file existed on the system.

    PNG tEXt chunks embed:
      - Thumb::URI       — original file path (proves file existed)
      - Thumb::MTime     — file modification time at thumbnail creation
      - Thumb::Size      — original file size
      - Thumb::Image::* — image dimensions (for images)
      - Thumb::Document::*  — for PDFs/docs
    """

    CACHE_DIRS = [
        ".cache/thumbnails/normal",
        ".cache/thumbnails/large",
        ".cache/thumbnails/x-large",
        ".cache/thumbnails/xx-large",
        ".cache/thumbnails/fail",
        ".thumbnails/normal",
        ".thumbnails/large",
    ]

    # PNG magic + tEXt chunk identifier
    PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
    TEXT_CHUNK = b"tEXt"
    ITXT_CHUNK = b"iTXt"

    def extract(self):
        entries = []
        for cache_rel in self.CACHE_DIRS:
            cache_dir = self.home_dir / cache_rel
            if not cache_dir.exists():
                continue
            for thumb_file in cache_dir.iterdir():
                if not thumb_file.suffix.lower() == ".png":
                    continue
                try:
                    metadata = self._parse_png_metadata(thumb_file)
                    if not metadata:
                        continue
                    uri = metadata.get("Thumb::URI", "")
                    mtime = metadata.get("Thumb::MTime", "")
                    size = metadata.get("Thumb::Size", "")
                    software = metadata.get("Software", "")

                    # Determine if the original file still exists
                    original_path = ""
                    still_exists = False
                    if uri.startswith("file://"):
                        original_path = uri[7:]
                        still_exists = os.path.exists(original_path)

                    entries.append({
                        "source": str(thumb_file),
                        "source_type": "Thumbnail Cache",
                        "cache_dir": cache_rel,
                        "thumbnail_file": thumb_file.name,
                        "original_uri": uri,
                        "original_path": original_path,
                        "file_still_exists": "YES" if still_exists else "NO — DELETED",
                        "original_mtime": mtime,
                        "original_size_bytes": size,
                        "software": software,
                        "all_metadata": str(metadata),
                        "extracted_at": datetime.datetime.now().isoformat(),
                    })
                except Exception as e:
                    self.errors.append(f"Thumbnail parse error ({thumb_file.name}): {e}")

        if not entries:
            entries.append({
                "source": "~/.cache/thumbnails/",
                "source_type": "Thumbnail Cache",
                "cache_dir": "N/A",
                "thumbnail_file": "N/A",
                "original_uri": "No thumbnail cache found or cache is empty.",
                "original_path": "", "file_still_exists": "N/A",
                "original_mtime": "", "original_size_bytes": "",
                "software": "", "all_metadata": "",
                "extracted_at": datetime.datetime.now().isoformat(),
            })

        self.results = entries
        return entries

    def _parse_png_metadata(self, png_path: Path) -> dict:
        """Parse PNG tEXt/iTXt chunks to extract thumbnail metadata."""
        metadata = {}
        try:
            with open(png_path, "rb") as f:
                header = f.read(8)
                if header != self.PNG_MAGIC:
                    return {}
                while True:
                    chunk_len_bytes = f.read(4)
                    if len(chunk_len_bytes) < 4:
                        break
                    chunk_len = struct.unpack(">I", chunk_len_bytes)[0]
                    chunk_type = f.read(4)
                    chunk_data = f.read(chunk_len)
                    f.read(4)  # CRC

                    if chunk_type in (self.TEXT_CHUNK, self.ITXT_CHUNK):
                        try:
                            # tEXt: key\x00value
                            null_idx = chunk_data.index(b"\x00")
                            key = chunk_data[:null_idx].decode("latin-1", errors="replace")
                            value = chunk_data[null_idx+1:].decode("latin-1", errors="replace").rstrip("\x00")
                            metadata[key] = value
                        except (ValueError, Exception):
                            pass

                    if chunk_type == b"IEND":
                        break
        except Exception:
            pass
        return metadata


# ═══════════════════════════════════════════════════════════════
#  ADVANCED FORENSIC MODULE 4 — JOURNAL LOG & SWAP CARVING
# ═══════════════════════════════════════════════════════════════

class JournalSwapExtractor(ForensicExtractor):
    """
    Two complementary techniques for recovering commands not in history files:

    A) journalctl — systemd journal stores terminal session metadata.
       Commands run in a graphical terminal (gnome-terminal, xterm, konsole)
       that write to the journal. Also captures sudo usage, authentication,
       and session open/close events — even when .bash_history was cleared.

    B) /proc/swaps + swap carving — When RAM is full, the kernel swaps
       process memory pages to disk. Shell command buffers (readline history,
       terminal emulator scroll buffers) may be paged out. We carve the swap
       space for command-like patterns. Requires root for swap device access.
    """

    CMD_PATTERN = re.compile(
        r"(?:sudo|apt|apt-get|git|ssh|scp|wget|curl|rm |mv |cp |cat |ls -|cd |"
        r"nano |vim |vi |python|python3|bash|sh |chmod|chown|grep|find|netcat|"
        r"nc |nmap|ping|ifconfig|ip addr|docker|systemctl|service|passwd|useradd|"
        r"history|shred|wipe|dd |mkfs|mount|umount|zip|tar |gzip|openssl|gpg|"
        r"iptables|ufw|cron|at |kill|pkill|ps aux|top|htop|strace|ltrace)"
        r"[^\n\r\x00]{3,150}"
    )

    def extract(self):
        entries = []
        entries += self._extract_journal()
        entries += self._extract_swap()
        if not entries:
            entries.append({
                "source": "journalctl / swap",
                "source_type": "Journal/Swap",
                "method": "N/A",
                "timestamp": "",
                "unit": "",
                "data": "No entries recovered. Journal may be empty or swap not accessible.",
                "extracted_at": datetime.datetime.now().isoformat(),
            })
        self.results = entries
        return entries

    def _extract_journal(self):
        entries = []
        try:
            # Try JSON output for structured data
            result = subprocess.run(
                ["journalctl", "--no-pager", "-o", "json", "-n", "2000",
                 "--since", "30 days ago"],
                capture_output=True, text=True, timeout=15
            )
            lines = result.stdout.strip().splitlines()
            for line in lines:
                try:
                    rec = json.loads(line)
                    msg = rec.get("MESSAGE", "")
                    unit = rec.get("_SYSTEMD_UNIT", rec.get("SYSLOG_IDENTIFIER", ""))
                    ts_us = rec.get("__REALTIME_TIMESTAMP", "")
                    ts = ""
                    if ts_us:
                        try:
                            ts = (datetime.datetime(1970,1,1) +
                                  datetime.timedelta(microseconds=int(ts_us))
                                  ).strftime("%Y-%m-%d %H:%M:%S")
                        except: ts = ts_us

                    # Filter for forensically relevant messages
                    if not msg:
                        continue
                    relevance = self._assess_relevance(msg, unit)
                    if not relevance:
                        continue

                    entries.append({
                        "source": "journalctl (systemd journal)",
                        "source_type": "Journal/Swap",
                        "method": "journalctl JSON",
                        "timestamp": ts,
                        "unit": unit,
                        "data": msg[:300],
                        "relevance": relevance,
                        "extracted_at": datetime.datetime.now().isoformat(),
                    })
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
            self.errors.append("journalctl not found — not a systemd system.")
        except subprocess.TimeoutExpired:
            self.errors.append("journalctl timed out.")
        except Exception as e:
            self.errors.append(f"journalctl error: {e}")

        # Fallback: plain text journal grep
        if not entries:
            try:
                result = subprocess.run(
                    ["journalctl", "--no-pager", "-n", "1000", "--since", "7 days ago"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if any(kw in line.lower() for kw in [
                        "sudo", "session opened", "session closed", "authentication",
                        "command", "failed password", "accepted password", "su:"
                    ]):
                        entries.append({
                            "source": "journalctl",
                            "source_type": "Journal/Swap",
                            "method": "journalctl plaintext",
                            "timestamp": line[:15] if len(line) > 15 else "",
                            "unit": "",
                            "data": line.strip()[:300],
                            "relevance": "Security Event",
                            "extracted_at": datetime.datetime.now().isoformat(),
                        })
            except Exception as e:
                self.errors.append(f"journalctl fallback error: {e}")

        return entries

    def _assess_relevance(self, msg: str, unit: str) -> str:
        msg_lower = msg.lower()
        unit_lower = unit.lower()
        if any(k in msg_lower for k in ["sudo", "su:", "su "]):
            return "Privilege Escalation"
        if any(k in msg_lower for k in ["session opened", "session closed"]):
            return "User Session"
        if any(k in msg_lower for k in ["authentication failure", "failed password", "invalid user"]):
            return "Auth Failure"
        if any(k in msg_lower for k in ["accepted password", "accepted publickey"]):
            return "Auth Success"
        if any(k in unit_lower for k in ["bash", "sh", "zsh", "terminal", "konsole", "gnome-terminal"]):
            return "Shell Activity"
        if self.CMD_PATTERN.search(msg):
            return "Command Pattern"
        if any(k in msg_lower for k in ["usb", "mount", "unmount", "device"]):
            return "Storage Event"
        if any(k in msg_lower for k in ["network", "wifi", "ethernet", "connected"]):
            return "Network Event"
        return ""

    def _extract_swap(self):
        entries = []
        try:
            with open("/proc/swaps", "r") as f:
                lines = f.readlines()[1:]  # skip header
        except (FileNotFoundError, PermissionError):
            self.errors.append("/proc/swaps not accessible.")
            return entries

        for line in lines:
            parts = line.split()
            if not parts:
                continue
            swap_dev = parts[0]
            entries.append({
                "source": swap_dev,
                "source_type": "Journal/Swap",
                "method": "Swap Device Detected",
                "timestamp": datetime.datetime.now().isoformat(),
                "unit": "kernel",
                "data": f"Swap partition/file detected: {swap_dev} (size: {parts[2] if len(parts)>2 else 'N/A'} KB). "
                        f"Root access required to carve this device for shell command strings.",
                "relevance": "Swap Partition",
                "extracted_at": datetime.datetime.now().isoformat(),
            })

            # Attempt swap carving (requires root)
            if os.geteuid() == 0:
                carved = self._carve_swap_device(swap_dev)
                entries += carved
            else:
                entries.append({
                    "source": swap_dev,
                    "source_type": "Journal/Swap",
                    "method": "Swap Carving (root required)",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "unit": "kernel",
                    "data": f"To carve swap for deleted command strings, run: sudo python3 hislilogger.py",
                    "relevance": "Swap Carving Unavailable",
                    "extracted_at": datetime.datetime.now().isoformat(),
                })

        return entries

    def _carve_swap_device(self, device: str) -> list:
        """Read swap in 1MB chunks and carve for command strings."""
        entries = []
        chunk_size = 1024 * 1024  # 1MB
        max_read = 50 * 1024 * 1024  # 50MB max
        bytes_read = 0
        carve_re = re.compile(
            rb"(?:sudo|apt-get|git clone|ssh |scp |wget |curl |rm -|history -c|"
            rb"shred |wipe |dd if|python3 |bash -|chmod |chown |nmap |netcat )"
            rb"[^\x00\n\r]{5,120}"
        )
        try:
            with open(device, "rb") as f:
                while bytes_read < max_read:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    for m in carve_re.finditer(chunk):
                        text = m.group(0).decode("utf-8", errors="replace").strip()
                        if text.isprintable():
                            entries.append({
                                "source": device,
                                "source_type": "Journal/Swap",
                                "method": "Swap Carving",
                                "timestamp": datetime.datetime.now().isoformat(),
                                "unit": "swap",
                                "data": text[:200],
                                "relevance": "Carved Command",
                                "extracted_at": datetime.datetime.now().isoformat(),
                            })
                    bytes_read += len(chunk)
        except (PermissionError, OSError) as e:
            self.errors.append(f"Swap carve error ({device}): {e}")
        return entries


# ═══════════════════════════════════════════════════════════════
#  KEYWORD DICTIONARY BUILDER
# ═══════════════════════════════════════════════════════════════

class KeywordDictionaryBuilder:
    STOP_WORDS = {
        "the", "and", "for", "are", "but", "not", "you", "all",
        "can", "had", "her", "was", "one", "our", "out", "day",
        "get", "has", "him", "his", "how", "its", "may", "new",
        "now", "old", "see", "two", "use", "way", "who", "did",
        "let", "put", "say", "she", "too",
    }

    def __init__(self, min_len: int = 3):
        self.min_len = min_len

    def build(self, text_sources: list) -> dict:
        counter = Counter()
        tok = re.compile(r"[a-zA-Z0-9_\-\.]+")
        for text in text_sources:
            for token in tok.findall(str(text)):
                t = token.lower()
                if len(t) >= self.min_len and t not in self.STOP_WORDS and not t.isdigit():
                    counter[t] += 1
        return dict(counter.most_common())

    def export_txt(self, kw_dict: dict, filepath: str):
        with open(filepath, "w") as f:
            f.write("# HisLiLogger - Keyword Dictionary\n")
            f.write(f"# Generated: {datetime.datetime.now()}\n")
            f.write(f"# Total unique keywords: {len(kw_dict)}\n\n")
            f.write(f"{'Keyword':<40} {'Count':>8}\n")
            f.write("-" * 50 + "\n")
            for word, count in kw_dict.items():
                f.write(f"{word:<40} {count:>8}\n")


# ═══════════════════════════════════════════════════════════════
#  MAIN GUI APPLICATION
# ═══════════════════════════════════════════════════════════════

class HisLiLoggerApp:
    APP_NAME = "HisLiLogger"
    VERSION  = "2.0.0"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{self.APP_NAME} v{self.VERSION} — Linux History Logger & Forensic Extractor")
        self.root.geometry("1200x780")
        self.root.minsize(1000, 640)

        # Standard data stores
        self.shell_entries   = []
        self.recent_entries  = []
        self.browser_entries = []
        self.keyword_dict    = {}

        # Advanced data stores
        self.proc_fd_entries    = []
        self.freelist_entries   = []
        self.thumbnail_entries  = []
        self.journal_entries    = []

        self.target_home      = tk.StringVar(value=str(Path.home()))
        self.min_keyword_len  = tk.IntVar(value=3)

        self._setup_styles()
        self._build_ui()

    # ── Styles ────────────────────────────────────────────────

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        BG     = "#0d1117"
        PANEL  = "#161b22"
        ACCENT = "#00d4aa"
        WARN   = "#f59e0b"
        DANGER = "#ef4444"
        TEXT   = "#e2e8f0"
        MUTED  = "#6e7681"
        BORDER = "#30363d"

        self.colors = {
            "bg": BG, "panel": PANEL, "accent": ACCENT,
            "warn": WARN, "danger": DANGER,
            "text": TEXT, "muted": MUTED, "border": BORDER,
        }
        self.root.configure(bg=BG)

        style.configure("TFrame",       background=BG)
        style.configure("Panel.TFrame", background=PANEL)

        style.configure("TLabel",      background=BG,    foreground=TEXT,   font=("Courier New", 10))
        style.configure("Header.TLabel",background=BG,   foreground=ACCENT, font=("Courier New", 18, "bold"))
        style.configure("Sub.TLabel",  background=BG,    foreground=MUTED,  font=("Courier New", 9))
        style.configure("Panel.TLabel",background=PANEL, foreground=TEXT,   font=("Courier New", 10))
        style.configure("Warn.TLabel", background=PANEL, foreground=WARN,   font=("Courier New", 9, "bold"))

        style.configure("Accent.TButton", background=ACCENT, foreground="#0d1117",
                        font=("Courier New", 10, "bold"), padding=(12,6))
        style.map("Accent.TButton", background=[("active","#00b894"),("pressed","#009e7f")])

        style.configure("Adv.TButton", background=WARN, foreground="#0d1117",
                        font=("Courier New", 10, "bold"), padding=(12,6))
        style.map("Adv.TButton", background=[("active","#d97706"),("pressed","#b45309")])

        style.configure("TButton", background=PANEL, foreground=TEXT,
                        font=("Courier New", 10), padding=(10,5))
        style.map("TButton", background=[("active",BORDER),("pressed","#374151")])

        style.configure("TNotebook",     background=BG,    borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                        font=("Courier New", 10), padding=(12,6))
        style.map("TNotebook.Tab",
                  background=[("selected",ACCENT)],
                  foreground=[("selected","#0d1117")])

        style.configure("Treeview",         background=PANEL, foreground=TEXT,
                        fieldbackground=PANEL, rowheight=24, font=("Courier New", 9))
        style.configure("Treeview.Heading", background=BORDER, foreground=ACCENT,
                        font=("Courier New", 9, "bold"))
        style.map("Treeview", background=[("selected",ACCENT)],
                  foreground=[("selected","#0d1117")])

        style.configure("TEntry",   fieldbackground=PANEL, foreground=TEXT,
                        insertcolor=ACCENT, font=("Courier New", 10))
        style.configure("TSpinbox", fieldbackground=PANEL, foreground=TEXT,
                        font=("Courier New", 10))

    # ── UI Construction ───────────────────────────────────────

    def _build_ui(self):
        c = self.colors

        # ─ Header ─
        hdr = ttk.Frame(self.root)
        hdr.pack(fill="x", padx=20, pady=(14,0))
        ttk.Label(hdr, text="⟨ HisLiLogger ⟩", style="Header.TLabel").pack(side="left")
        ttk.Label(hdr, text="  Linux History Logger & Forensic Extractor  v2.0",
                  style="Sub.TLabel").pack(side="left", padx=(8,0), pady=(8,0))

        tk.Frame(self.root, bg=c["accent"], height=1).pack(fill="x", padx=20, pady=6)

        # ─ Config bar ─
        self._build_config_bar()

        # ─ Two-notebook layout: Standard | Advanced — split by draggable sash ─
        paned = ttk.PanedWindow(self.root, orient="vertical")
        paned.pack(fill="both", expand=True, padx=20, pady=(0,2))

        # ── Standard pane ──
        lf_std = ttk.Frame(paned)
        paned.add(lf_std, weight=1)

        std_hdr = ttk.Frame(lf_std, style="Panel.TFrame")
        std_hdr.pack(fill="x")
        ttk.Label(std_hdr, text=" ◈ STANDARD EXTRACTION", style="Panel.TLabel",
                  font=("Courier New", 9, "bold")).pack(side="left", padx=8, pady=3)

        self.nb_std = ttk.Notebook(lf_std)
        self.nb_std.pack(fill="both", expand=True)

        self.tab_shell    = ttk.Frame(self.nb_std)
        self.tab_recent   = ttk.Frame(self.nb_std)
        self.tab_browser  = ttk.Frame(self.nb_std)
        self.tab_keywords = ttk.Frame(self.nb_std)
        self.tab_log      = ttk.Frame(self.nb_std)

        self.nb_std.add(self.tab_shell,    text="  Shell History  ")
        self.nb_std.add(self.tab_recent,   text="  Recently Used  ")
        self.nb_std.add(self.tab_browser,  text="  Browser History  ")
        self.nb_std.add(self.tab_keywords, text="  Keyword Dictionary  ")
        self.nb_std.add(self.tab_log,      text="  Forensic Log  ")

        self._build_shell_tab()
        self._build_recent_tab()
        self._build_browser_tab()
        self._build_keywords_tab()
        self._build_log_tab()

        # ── Advanced pane ──
        lf_adv = ttk.Frame(paned)
        paned.add(lf_adv, weight=1)

        adv_hdr = ttk.Frame(lf_adv, style="Panel.TFrame")
        adv_hdr.pack(fill="x")
        ttk.Label(adv_hdr, text=" ⚠ ADVANCED FORENSIC MODULES — Deleted/Hidden Artifact Recovery",
                  style="Warn.TLabel").pack(side="left", padx=8, pady=3)

        self.nb_adv = ttk.Notebook(lf_adv)
        self.nb_adv.pack(fill="both", expand=True)

        self.tab_procfd     = ttk.Frame(self.nb_adv)
        self.tab_freelist   = ttk.Frame(self.nb_adv)
        self.tab_thumbnails = ttk.Frame(self.nb_adv)
        self.tab_journal    = ttk.Frame(self.nb_adv)

        self.nb_adv.add(self.tab_procfd,     text="  [ADV-1] /proc/fd Deleted History  ")
        self.nb_adv.add(self.tab_freelist,   text="  [ADV-2] SQLite Freelist Recovery  ")
        self.nb_adv.add(self.tab_thumbnails, text="  [ADV-3] Thumbnail Cache  ")
        self.nb_adv.add(self.tab_journal,    text="  [ADV-4] Journal & Swap Carving  ")

        self._build_procfd_tab()
        self._build_freelist_tab()
        self._build_thumbnails_tab()
        self._build_journal_tab()

        # ── Bottom bar ──
        self._build_bottom_bar()

    def _build_config_bar(self):
        bar = ttk.Frame(self.root, style="Panel.TFrame")
        bar.pack(fill="x", padx=20, pady=3)

        ttk.Label(bar, text=" Target Home:", style="Panel.TLabel").pack(side="left", padx=(8,4))
        ttk.Entry(bar, textvariable=self.target_home, width=40).pack(side="left", padx=4)
        ttk.Button(bar, text="Browse", command=self._browse_home).pack(side="left", padx=4)

        ttk.Label(bar, text=" | Min KW Len:", style="Panel.TLabel").pack(side="left", padx=(10,4))
        ttk.Spinbox(bar, from_=3, to=20, textvariable=self.min_keyword_len, width=4).pack(side="left")

        ttk.Button(bar, text="▶ EXTRACT ALL", style="Accent.TButton",
                   command=self._run_all).pack(side="right", padx=4)
        ttk.Button(bar, text="⚠ RUN ADVANCED", style="Adv.TButton",
                   command=self._run_advanced).pack(side="right", padx=4)
        ttk.Button(bar, text="▷ Standard Only", command=self._run_standard).pack(side="right", padx=4)

        self.status_var = tk.StringVar(value="Ready — click EXTRACT ALL or run modules individually")
        ttk.Label(bar, textvariable=self.status_var, style="Panel.TLabel").pack(side="left", padx=10)

    # ── Standard tabs ──────────────────────────

    def _build_shell_tab(self):
        self.shell_tree = self._make_tree(self.tab_shell,
            ("Shell", "Line", "Command", "Source"), (130, 55, 480, 240))

    def _build_recent_tab(self):
        self.recent_tree = self._make_tree(self.tab_recent,
            ("Filename", "MIME", "Last Visited", "URI"), (200, 170, 150, 380))

    def _build_browser_tab(self):
        self.browser_tree = self._make_tree(self.tab_browser,
            ("Browser", "Profile", "Title", "Visits", "Last Visit", "URL"), (130, 90, 200, 55, 150, 360))

    def _build_keywords_tab(self):
        top = ttk.Frame(self.tab_keywords)
        top.pack(fill="both", expand=True)
        self.kw_tree = self._make_tree(top, ("Keyword","Count","Length"), (280,110,70))
        info = ttk.Frame(self.tab_keywords, style="Panel.TFrame")
        info.pack(fill="x", side="bottom")
        self.kw_stats = tk.StringVar(value="No keywords extracted yet.")
        ttk.Label(info, textvariable=self.kw_stats, style="Panel.TLabel").pack(side="left", padx=8, pady=4)
        ttk.Button(info, text="Export Keyword Dictionary",
                   command=self._export_keywords).pack(side="right", padx=8, pady=4)

    def _build_log_tab(self):
        c = self.colors
        self.log_text = scrolledtext.ScrolledText(
            self.tab_log, bg=c["panel"], fg=c["text"],
            font=("Courier New", 9), insertbackground=c["accent"],
            wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        self._log("HisLiLogger v2.0 — Forensic Log initialized.")
        self._log(f"Started: {datetime.datetime.now()}")
        self._log("-" * 60)

    # ── Advanced tabs ───────────────────────────

    def _build_procfd_tab(self):
        c = self.colors
        info = ttk.Frame(self.tab_procfd, style="Panel.TFrame")
        info.pack(fill="x")
        ttk.Label(info, style="Warn.TLabel",
                  text="  Scans /proc/<pid>/fd for open file descriptors pointing to deleted "
                       "history files. Recovers content even after 'rm ~/.bash_history'."
                  ).pack(side="left", padx=8, pady=4)
        self.procfd_tree = self._make_tree(self.tab_procfd,
            ("PID", "FD", "File", "Status", "Line", "Command"),
            (70, 50, 130, 260, 50, 380))

    def _build_freelist_tab(self):
        info = ttk.Frame(self.tab_freelist, style="Panel.TFrame")
        info.pack(fill="x")
        ttk.Label(info, style="Warn.TLabel",
                  text="  Parses SQLite freelist pages (Firefox/Chrome DB) to recover deleted "
                       "browsing history rows that SQLite marks free but doesn't zero."
                  ).pack(side="left", padx=8, pady=4)
        self.freelist_tree = self._make_tree(self.tab_freelist,
            ("DB", "Type", "Page No", "Offset", "Recovered Data"),
            (160, 120, 80, 80, 480))

    def _build_thumbnails_tab(self):
        info = ttk.Frame(self.tab_thumbnails, style="Panel.TFrame")
        info.pack(fill="x")
        ttk.Label(info, style="Warn.TLabel",
                  text="  Extracts PNG metadata from ~/.cache/thumbnails/ — "
                       "proves a file existed even after deletion (URI + MTime embedded in thumbnail)."
                  ).pack(side="left", padx=8, pady=4)
        self.thumb_tree = self._make_tree(self.tab_thumbnails,
            ("Original File", "Still Exists?", "Orig MTime", "Size (B)", "Cache Dir", "Thumbnail"),
            (280, 110, 160, 80, 160, 240))

    def _build_journal_tab(self):
        info = ttk.Frame(self.tab_journal, style="Panel.TFrame")
        info.pack(fill="x")
        ttk.Label(info, style="Warn.TLabel",
                  text="  Extracts forensic events from systemd journal (sudo, sessions, auth) "
                       "and detects swap partitions for command carving (root required for swap)."
                  ).pack(side="left", padx=8, pady=4)
        self.journal_tree = self._make_tree(self.tab_journal,
            ("Method", "Timestamp", "Relevance", "Unit", "Data"),
            (160, 150, 150, 130, 440))

    # ── Bottom export bar ──────────────────────

    def _build_bottom_bar(self):
        bar = ttk.Frame(self.root, style="Panel.TFrame")
        bar.pack(fill="x", padx=20, pady=(0,6))
        ttk.Button(bar, text="Export Shell (.txt)",
                   command=lambda: self._export_txt("shell")).pack(side="left", padx=3, pady=4)
        ttk.Button(bar, text="Export Browser (.txt)",
                   command=lambda: self._export_txt("browser")).pack(side="left", padx=3, pady=4)
        ttk.Button(bar, text="Export ALL (.txt)",
                   command=lambda: self._export_txt("all")).pack(side="left", padx=3, pady=4)
        ttk.Button(bar, text="Export Advanced (.txt)",
                   command=self._export_advanced).pack(side="left", padx=3, pady=4)
        ttk.Button(bar, text="Export Full Forensic Report",
                   command=self._export_report).pack(side="left", padx=3, pady=4)
        ttk.Button(bar, text="Clear All",
                   command=self._clear_all).pack(side="right", padx=3, pady=4)

    # ── Helper: Treeview factory ───────────────

    def _make_tree(self, parent, columns, widths):
        c = self.colors
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=4, pady=4)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        for col, w in zip(columns, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, minwidth=40)
        vsb = ttk.Scrollbar(frame, orient="vertical",   command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        menu = tk.Menu(tree, tearoff=0, bg=c["panel"], fg=c["text"])
        menu.add_command(label="Copy selected", command=lambda: self._copy_selection(tree))
        tree.bind("<Button-3>", lambda e: menu.post(e.x_root, e.y_root))
        return tree

    # ── Extraction orchestrators ───────────────

    def _browse_home(self):
        p = filedialog.askdirectory(initialdir=self.target_home.get())
        if p: self.target_home.set(p)

    def _run_all(self):
        self._set_status("Running all modules...")
        def _all_worker():
            self._std_worker()
            self._adv_worker()
        threading.Thread(target=_all_worker, daemon=True).start()

    def _run_standard(self):
        self._set_status("Running standard extraction...")
        threading.Thread(target=self._std_worker, daemon=True).start()

    def _run_advanced(self):
        self._set_status("Running advanced forensic modules...")
        threading.Thread(target=self._adv_worker, daemon=True).start()

    # ── Standard worker ────────────────────────

    def _std_worker(self):
        home = self.target_home.get()
        if not os.path.isdir(home):
            self.root.after(0, lambda: messagebox.showerror("Error", f"Not a directory:\n{home}"))
            return

        self._log(f"\n[STANDARD EXTRACTION] Target: {home}")
        self._log(f"Time: {datetime.datetime.now()}")

        self._log("\n[1] Shell History...")
        ext = ShellHistoryExtractor(home)
        self.shell_entries = ext.extract()
        for e in ext.errors: self._log(f"  WARN: {e}")
        self._log(f"  → {len(self.shell_entries)} commands")

        self._log("\n[2] Recently Used Files...")
        ext2 = RecentlyUsedExtractor(home)
        self.recent_entries = ext2.extract()
        for e in ext2.errors: self._log(f"  WARN: {e}")
        self._log(f"  → {len(self.recent_entries)} entries")

        self._log("\n[3] Browser History...")
        ext3 = BrowserHistoryExtractor(home)
        # Log every path checked so the Forensic Log shows exactly what was found/missing
        for base_rel, bname in ext3.FIREFOX_BASED:
            p = Path(home) / base_rel
            self._log(f"  [FF ] {bname}: {'FOUND' if p.exists() else 'not found'}  ({p})")
        for base_rel, bname in ext3.CHROMIUM_BASED:
            p = Path(home) / base_rel
            self._log(f"  [CR ] {bname}: {'FOUND' if p.exists() else 'not found'}  ({p})")
        self.browser_entries = ext3.extract()
        for e in ext3.errors: self._log(f"  WARN: {e}")
        per_browser = Counter(e["source_type"] for e in self.browser_entries)
        for bname, cnt in per_browser.items():
            self._log(f"  → {bname}: {cnt} URLs")
        self._log(f"  → TOTAL: {len(self.browser_entries)} URLs")

        self._log("\n[4] Keyword Dictionary...")
        try:
            min_len = self.min_keyword_len.get()
        except Exception:
            min_len = 3
        sources = (
            [e.get("command","") for e in self.shell_entries]
            + [e.get("filename","") + " " + e.get("file_uri","") for e in self.recent_entries]
            + [e.get("url","")+" "+e.get("title","") for e in self.browser_entries]
        )
        self.keyword_dict = KeywordDictionaryBuilder(min_len).build(sources)
        self._log(f"  → {len(self.keyword_dict)} keywords")
        self._log("[STANDARD COMPLETE]")

        self.root.after(0, self._populate_standard)

    # ── Advanced worker ────────────────────────

    def _adv_worker(self):
        home = self.target_home.get()
        self._log(f"\n[ADVANCED FORENSIC MODULES] Target: {home}")
        self._log(f"Time: {datetime.datetime.now()}")

        self._log("\n[ADV-1] /proc/fd Deleted History Recovery...")
        ext = ProcFdDeletedHistoryExtractor(home)
        self.proc_fd_entries = ext.extract()
        for e in ext.errors: self._log(f"  WARN: {e}")
        self._log(f"  → {len(self.proc_fd_entries)} entries")

        self._log("\n[ADV-2] SQLite Freelist Recovery...")
        ext2 = SQLiteFreelistRecovery(home)
        self.freelist_entries = ext2.extract()
        for e in ext2.errors: self._log(f"  WARN: {e}")
        self._log(f"  → {len(self.freelist_entries)} recovered records")

        self._log("\n[ADV-3] Thumbnail Cache Forensics...")
        ext3 = ThumbnailCacheExtractor(home)
        self.thumbnail_entries = ext3.extract()
        for e in ext3.errors: self._log(f"  WARN: {e}")
        deleted = sum(1 for e in self.thumbnail_entries if e.get("file_still_exists","") == "NO — DELETED")
        self._log(f"  → {len(self.thumbnail_entries)} thumbnails ({deleted} for deleted files)")

        self._log("\n[ADV-4] Journal & Swap Carving...")
        ext4 = JournalSwapExtractor(home)
        self.journal_entries = ext4.extract()
        for e in ext4.errors: self._log(f"  WARN: {e}")
        self._log(f"  → {len(self.journal_entries)} events")

        self._log("[ADVANCED COMPLETE]")
        self.root.after(0, self._populate_advanced)
        self.root.after(0, lambda: self._set_status(
            f"Done! Shell:{len(self.shell_entries)} Browser:{len(self.browser_entries)} | "
            f"ADV — /proc:{len(self.proc_fd_entries)} Freelist:{len(self.freelist_entries)} "
            f"Thumbs:{len(self.thumbnail_entries)} Journal:{len(self.journal_entries)}"
        ))

    # ── Populate standard UI ───────────────────

    def _populate_standard(self):
        self._clear_tree(self.shell_tree)
        for e in self.shell_entries:
            self.shell_tree.insert("","end", values=(
                Path(e["shell"]).name, e["line_no"], e["command"], e["source"]))

        self._clear_tree(self.recent_tree)
        for e in self.recent_entries:
            self.recent_tree.insert("","end", values=(
                e["filename"], e["mime_type"],
                e["visited"][:19] if e["visited"] else "", e["file_uri"]))

        self._clear_tree(self.browser_tree)
        for e in self.browser_entries:
            self.browser_tree.insert("","end", values=(
                e["source_type"], e.get("profile",""),
                e.get("title","")[:50],
                e.get("visit_count",""), e.get("last_visit",""), e.get("url","")))

        self._clear_tree(self.kw_tree)
        for w, c in self.keyword_dict.items():
            self.kw_tree.insert("","end", values=(w, c, len(w)))
        self.kw_stats.set(
            f"Keywords: {len(self.keyword_dict)}  |  Shell: {len(self.shell_entries)}  |  "
            f"Recent: {len(self.recent_entries)}  |  Browser: {len(self.browser_entries)}")
        self._set_status(
            f"Standard done — Shell:{len(self.shell_entries)} Recent:{len(self.recent_entries)} "
            f"Browser:{len(self.browser_entries)} KW:{len(self.keyword_dict)}")

    # ── Populate advanced UI ───────────────────

    def _populate_advanced(self):
        self._clear_tree(self.procfd_tree)
        for e in self.proc_fd_entries:
            self.procfd_tree.insert("","end", values=(
                e.get("pid",""), e.get("fd",""), e.get("file",""),
                e.get("status",""), e.get("line_no",""), e.get("command","")))

        self._clear_tree(self.freelist_tree)
        for e in self.freelist_entries:
            self.freelist_tree.insert("","end", values=(
                e.get("db_name",""), e.get("record_type",""),
                e.get("page_no",""), e.get("offset",""),
                e.get("recovered_data","")[:120]))

        self._clear_tree(self.thumb_tree)
        for e in self.thumbnail_entries:
            tag = "deleted" if e.get("file_still_exists","") == "NO — DELETED" else ""
            iid = self.thumb_tree.insert("","end", values=(
                e.get("original_path","") or e.get("original_uri",""),
                e.get("file_still_exists",""),
                e.get("original_mtime",""),
                e.get("original_size_bytes",""),
                e.get("cache_dir",""),
                e.get("thumbnail_file","")))
            if tag == "deleted":
                self.thumb_tree.item(iid, tags=("deleted",))
        # Highlight deleted file rows in orange
        self.thumb_tree.tag_configure("deleted", foreground=self.colors["warn"])

        self._clear_tree(self.journal_tree)
        for e in self.journal_entries:
            self.journal_tree.insert("","end", values=(
                e.get("method",""), e.get("timestamp",""),
                e.get("relevance",""), e.get("unit",""),
                e.get("data","")[:200]))

    # ── Exports ────────────────────────────────

    def _export_txt(self, mode="all"):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")],
            initialfile=f"hislilogger_{mode}_{datetime.date.today()}.txt")
        if not path: return
        try:
            with open(path,"w") as f:
                f.write("="*70+"\n")
                f.write(f"  HisLiLogger v2.0 Export — {mode.upper()}\n")
                f.write(f"  Generated: {datetime.datetime.now()}\n")
                f.write(f"  Target: {self.target_home.get()}\n")
                f.write("="*70+"\n\n")
                if mode in ("shell","all") and self.shell_entries:
                    f.write(f"\n{'─'*60}\n  SHELL HISTORY ({len(self.shell_entries)})\n{'─'*60}\n")
                    for e in self.shell_entries:
                        f.write(f"[{e['shell']}:{e['line_no']}] {e['command']}\n")
                if mode == "all" and self.recent_entries:
                    f.write(f"\n{'─'*60}\n  RECENTLY USED ({len(self.recent_entries)})\n{'─'*60}\n")
                    for e in self.recent_entries:
                        f.write(f"{e.get('visited','')[:19]:20}  {e['file_uri']}\n")
                if mode in ("browser","all") and self.browser_entries:
                    f.write(f"\n{'─'*60}\n  BROWSER HISTORY ({len(self.browser_entries)})\n{'─'*60}\n")
                    for e in self.browser_entries:
                        f.write(f"[{e['source_type']}][{e.get('profile','')}][{e.get('last_visit','')}][v:{e.get('visit_count','')}]  {e.get('url','')}\n")
            self._log(f"[EXPORT] {mode} → {path}")
            messagebox.showinfo("Saved", f"Saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("Export Error", str(ex))

    def _export_advanced(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")],
            initialfile=f"hislilogger_advanced_{datetime.date.today()}.txt")
        if not path: return
        try:
            with open(path,"w") as f:
                f.write("="*70+"\n")
                f.write("  HisLiLogger v2.0 — ADVANCED FORENSIC MODULES EXPORT\n")
                f.write(f"  Generated: {datetime.datetime.now()}\n")
                f.write("="*70+"\n\n")

                f.write(f"\n{'─'*60}\n  [ADV-1] /proc/fd DELETED HISTORY ({len(self.proc_fd_entries)})\n{'─'*60}\n")
                for e in self.proc_fd_entries:
                    f.write(f"  PID:{e.get('pid','')} FD:{e.get('fd','')} File:{e.get('file','')} Status:{e.get('status','')}\n")
                    if e.get('command'): f.write(f"    CMD: {e['command']}\n")

                f.write(f"\n{'─'*60}\n  [ADV-2] SQLITE FREELIST RECOVERED ({len(self.freelist_entries)})\n{'─'*60}\n")
                for e in self.freelist_entries:
                    f.write(f"  [{e.get('record_type','')}] DB:{e.get('db_name','')} Page:{e.get('page_no','')} Offset:{e.get('offset','')}\n")
                    f.write(f"    DATA: {e.get('recovered_data','')[:200]}\n")

                f.write(f"\n{'─'*60}\n  [ADV-3] THUMBNAIL CACHE ({len(self.thumbnail_entries)})\n{'─'*60}\n")
                for e in self.thumbnail_entries:
                    f.write(f"  Original: {e.get('original_path') or e.get('original_uri','')}\n")
                    f.write(f"    Still exists: {e.get('file_still_exists','')} | MTime: {e.get('original_mtime','')} | Size: {e.get('original_size_bytes','')} B\n")

                f.write(f"\n{'─'*60}\n  [ADV-4] JOURNAL/SWAP ({len(self.journal_entries)})\n{'─'*60}\n")
                for e in self.journal_entries:
                    f.write(f"  [{e.get('relevance','')}] {e.get('timestamp','')} [{e.get('unit','')}]\n")
                    f.write(f"    {e.get('data','')[:300]}\n")

            self._log(f"[EXPORT] Advanced → {path}")
            messagebox.showinfo("Saved", f"Advanced export saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("Export Error", str(ex))

    def _export_keywords(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")],
            initialfile=f"keywords_{datetime.date.today()}.txt")
        if not path: return
        try:
            try:
                min_len = self.min_keyword_len.get()
            except Exception:
                min_len = 3
            KeywordDictionaryBuilder(min_len).export_txt(self.keyword_dict, path)
            messagebox.showinfo("Saved", f"Keywords saved:\n{path}")
        except Exception as ex:
            messagebox.showerror("Export Error", str(ex))

    def _export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text","*.txt")],
            initialfile=f"HisLiLogger_Report_{datetime.date.today()}.txt")
        if not path: return
        try:
            with open(path,"w") as f:
                f.write("="*70+"\n")
                f.write("  HisLiLogger v2.0 — COMPLETE FORENSIC INVESTIGATION REPORT\n")
                f.write(f"  Date: {datetime.datetime.now()}\n")
                f.write(f"  Target: {self.target_home.get()}\n")
                f.write("="*70+"\n\n")

                f.write("EXECUTIVE SUMMARY\n"+"-"*40+"\n")
                f.write(f"  Shell commands             : {len(self.shell_entries)}\n")
                f.write(f"  Recently used files        : {len(self.recent_entries)}\n")
                f.write(f"  Browser history records    : {len(self.browser_entries)}\n")
                f.write(f"  Unique keywords            : {len(self.keyword_dict)}\n")
                f.write(f"  /proc/fd deleted history   : {len(self.proc_fd_entries)}\n")
                f.write(f"  SQLite freelist recovered  : {len(self.freelist_entries)}\n")
                deleted_thumbs = sum(1 for e in self.thumbnail_entries
                                     if e.get("file_still_exists","") == "NO — DELETED")
                f.write(f"  Thumbnail artifacts        : {len(self.thumbnail_entries)} ({deleted_thumbs} for deleted files)\n")
                f.write(f"  Journal/Swap events        : {len(self.journal_entries)}\n\n")

                # Chain of custody
                f.write("CHAIN OF CUSTODY — SHA-256 FILE HASHES\n"+"-"*40+"\n")
                seen = {}
                for e in (self.shell_entries + self.recent_entries +
                          self.browser_entries + self.freelist_entries):
                    src = e.get("source","")
                    if src and src not in seen:
                        seen[src] = e.get("file_hash","N/A")
                for src,h in seen.items():
                    f.write(f"  {src}\n    SHA-256: {h}\n")

                # All sections
                sections = [
                    ("SHELL HISTORY", self.shell_entries,
                     lambda e: f"[{e['shell']}:{e['line_no']}] {e['command']}"),
                    ("RECENTLY USED FILES", self.recent_entries,
                     lambda e: f"  {e.get('visited','')[:19]:20}  {e['file_uri']}"),
                    ("BROWSER HISTORY", self.browser_entries,
                     lambda e: f"  [{e['source_type']}][{e.get('profile','')}] {e.get('last_visit','')}  {e.get('url','')}"),
                    ("[ADV-1] /proc/fd DELETED HISTORY", self.proc_fd_entries,
                     lambda e: f"  PID:{e.get('pid','')} {e.get('status','')}  CMD:{e.get('command','')}"),
                    ("[ADV-2] SQLITE FREELIST RECOVERED", self.freelist_entries,
                     lambda e: f"  [{e.get('record_type','')}] Page:{e.get('page_no','')}  {e.get('recovered_data','')[:150]}"),
                    ("[ADV-3] THUMBNAIL CACHE", self.thumbnail_entries,
                     lambda e: f"  [{e.get('file_still_exists','')}] MTime:{e.get('original_mtime','')}  {e.get('original_path') or e.get('original_uri','')}"),
                    ("[ADV-4] JOURNAL/SWAP", self.journal_entries,
                     lambda e: f"  [{e.get('relevance','')}] {e.get('timestamp','')}  {e.get('data','')[:200]}"),
                ]
                for title, entries, fmt in sections:
                    f.write(f"\n\n{title} ({len(entries)} entries)\n{'─'*60}\n")
                    for e in entries:
                        try: f.write(fmt(e)+"\n")
                        except: pass

                f.write(f"\n\nTOP 50 KEYWORDS\n{'─'*40}\n")
                for w,c in list(self.keyword_dict.items())[:50]:
                    f.write(f"  {w:<35} {c}\n")

            self._log(f"[EXPORT] Full report → {path}")
            messagebox.showinfo("Report Saved", f"Full forensic report:\n{path}")
        except Exception as ex:
            messagebox.showerror("Export Error", str(ex))

    # ── Utilities ──────────────────────────────

    def _log(self, msg):
        def _do():
            self.log_text.config(state="normal")
            self.log_text.insert("end", msg+"\n")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.root.after(0, _do)

    def _set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    def _clear_tree(self, tree):
        for item in tree.get_children():
            tree.delete(item)

    def _copy_selection(self, tree):
        sel = tree.selection()
        if not sel: return
        rows = ["\t".join(str(v) for v in tree.item(s,"values")) for s in sel]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(rows))

    def _clear_all(self):
        for tree in [self.shell_tree, self.recent_tree, self.browser_tree, self.kw_tree,
                     self.procfd_tree, self.freelist_tree, self.thumb_tree, self.journal_tree]:
            self._clear_tree(tree)
        self.shell_entries = []
        self.recent_entries = []
        self.browser_entries = []
        self.proc_fd_entries = []
        self.freelist_entries = []
        self.thumbnail_entries = []
        self.journal_entries = []
        self.keyword_dict={}
        self.kw_stats.set("No keywords extracted yet.")
        self._set_status("Cleared. Ready.")
        self._log("[CLEARED] All data cleared.")


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    app = HisLiLoggerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()