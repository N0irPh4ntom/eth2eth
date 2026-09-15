# -*- coding: utf-8 -*-
"""
ETH Transfer Toolkit
====================
Single-sided GUI file pusher over Ethernet (SMB) for Windows.

Core:
  * Runs ONLY on the sending PC (Win11 or Win7, both directions work).
  * The target PC needs nothing installed - just Windows' SMB sharing.
  * 4 MB unbuffered chunks + parallel streams -> near line-rate.

Extras in this build:
  * Resume partial files (.part survives cancel/network errors)
  * Per-file retry with exponential backoff
  * Delta sync (skip unchanged: size / size+mtime / sha256)
  * SHA-256 verification option
  * Bandwidth limiter (global token bucket)
  * Saved profiles with DPAPI-encrypted passwords
  * Wake-on-LAN button
  * LAN scanner (finds SMB hosts on the subnet)
  * Robocopy engine fallback
  * CLI mode for scripting / Task Scheduler

Requires: Python 3.8+ (tkinter bundled with python.org installer).
No third-party packages.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter.scrolledtext import ScrolledText

# --------------------------------------------------------------------------- #
#  Config
# --------------------------------------------------------------------------- #
IS_WIN = os.name == "nt"
CHUNK = 4 * 1024 * 1024
CREATE_NO_WINDOW = 0x08000000
APP_NAME = "ETH Transfer Toolkit"

PROFILE_DIR = os.path.join(
    os.environ.get("APPDATA") or os.path.expanduser("~"), "eth2eth"
)
PROFILE_FILE = os.path.join(PROFILE_DIR, "profiles.json")


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #
class Cancelled(Exception):
    pass


def run_hidden(args, timeout=None):
    """Run a console command without flashing a black window."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return subprocess.run(
        args,
        startupinfo=si,
        capture_output=True,
        text=True,
        errors="replace",
        creationflags=CREATE_NO_WINDOW,
        timeout=timeout,
    )


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.2f} {unit}"
        n /= 1024


def human_time(sec):
    if sec <= 0 or sec > 86400 * 7:
        return "--:--"
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def norm_host(raw: str) -> str:
    h = raw.strip()
    for p in ("smb://", "\\\\", "http://", "https://"):
        if h.lower().startswith(p):
            h = h[len(p):]
    return h.strip("\\/ ").split("\\")[0].split("/")[0]


def build_unc(host: str, share: str, remote_path: str) -> str:
    r"""\\host\share + a Windows path (C:\a\b or \a\b) -> full UNC path."""
    p = (remote_path or "").strip()
    if p.startswith("\\\\"):
        return p.rstrip("\\")
    share = share.strip().strip("\\/") or "C$"
    p = p.lstrip("\\/")
    if len(p) >= 2 and p[1] == ":":
        p = p[2:]
    p = p.lstrip("\\/")
    unc = f"\\\\{host}\\{share}"
    return unc + ("\\" + p.replace("/", "\\") if p else "")


def probe_host(host):
    """Return (ping_ok, smb_ok)."""
    ping_ok = False
    try:
        r = run_hidden(["ping", "-n", "1", "-w", "1200", host], timeout=6)
        ping_ok = r.returncode == 0
    except Exception:
        pass

    smb_ok = False
    s = socket.socket()
    s.settimeout(3)
    try:
        s.connect((host, 445))
        smb_ok = True
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return ping_ok, smb_ok


def smb_connect(host, share, user, password, log):
    r"""Mount \\host\share with the given credentials (auto-cleans stale session)."""
    unc = f"\\\\{host}\\{share.strip().strip(chr(92) + '/')}"
    run_hidden(["net", "use", unc, "/delete", "/y"])

    args = ["net", "use", unc]
    if password:
        args.append(password)
    if user:
        args.append(f"/user:{user}")

    r = run_hidden(args, timeout=25)
    if r.returncode != 0:
        raise RuntimeError(
            f"Could not mount {unc}\n\n"
            f"{(r.stdout or '').strip()}\n{(r.stderr or '').strip()}\n\n"
            "Check: host reachable, account is a local admin on the target, "
            "password correct (for a Microsoft account use "
            "'MicrosoftAccount\\you@mail.com'), and File & Printer Sharing "
            "is enabled on the target."
        )
    log(f"Mounted {unc}")
    return unc


def smb_disconnect(unc):
    try:
        run_hidden(["net", "use", unc, "/delete", "/y"], timeout=10)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
#  Hashing / delta / rate-limit
# --------------------------------------------------------------------------- #
def sha256_file(path, cancel=None, chunk=CHUNK):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def unchanged(src, dst, policy="size+mtime", cancel=None):
    """Return True if dst can be safely considered identical to src."""
    try:
        if not os.path.isfile(dst):
            return False
        ss = os.path.getsize(src)
        ds = os.path.getsize(dst)
        if ss != ds:
            return False
        if policy == "size":
            return True
        if policy == "size+mtime":
            # 2 s slack covers FAT timestamp granularity.
            return os.path.getmtime(src) <= os.path.getmtime(dst) + 2
        if policy == "sha256":
            return sha256_file(src, cancel) == sha256_file(dst, cancel)
    except OSError:
        return False
    return False


class RateLimiter:
    """Global token bucket shared across all worker threads."""
    __slots__ = ("rate", "allowance", "last", "_lk")

    def __init__(self, bytes_per_sec):
        self.rate = float(bytes_per_sec or 0)
        self.allowance = self.rate
        self.last = time.monotonic()
        self._lk = threading.Lock()

    def consume(self, n):
        if self.rate <= 0:
            return
        with self._lk:
            now = time.monotonic()
            self.allowance = min(
                self.rate, self.allowance + (now - self.last) * self.rate
            )
            self.last = now
            self.allowance -= n
            wait = max(0.0, -self.allowance / self.rate)
        if wait > 0:
            time.sleep(wait)


# --------------------------------------------------------------------------- #
#  DPAPI (per-user encryption for stored passwords)
# --------------------------------------------------------------------------- #
class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_ulong),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


_crypt32 = None
_kernel32 = None


def _init_dpapi():
    global _crypt32, _kernel32
    if _crypt32 is None:
        _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


def _blob_from_bytes(data: bytes):
    buf = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf


def dpapi_encrypt(data: bytes) -> bytes:
    _init_dpapi()
    bin_, _keep = _blob_from_bytes(data)
    bout = _DataBlob()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(bin_), None, None, None, None, 0, ctypes.byref(bout)
    )
    if not ok:
        raise OSError(f"CryptProtectData failed ({ctypes.get_last_error()})")
    try:
        return ctypes.string_at(bout.pbData, bout.cbData)
    finally:
        _kernel32.LocalFree(bout.pbData)


def dpapi_decrypt(data: bytes) -> bytes:
    _init_dpapi()
    bin_, _keep = _blob_from_bytes(data)
    bout = _DataBlob()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(bin_), None, None, None, None, 0, ctypes.byref(bout)
    )
    if not ok:
        raise OSError(f"CryptUnprotectData failed ({ctypes.get_last_error()})")
    try:
        return ctypes.string_at(bout.pbData, bout.cbData)
    finally:
        _kernel32.LocalFree(bout.pbData)


def _encrypt_pwd(plain: str) -> str:
    if not plain:
        return ""
    try:
        return "dpapi:" + base64.b64encode(
            dpapi_encrypt(plain.encode("utf-8"))
        ).decode("ascii")
    except Exception:
        # Fallback: base64 only (obfuscation, not security).
        return "plain:" + base64.b64encode(plain.encode("utf-8")).decode("ascii")


def _decrypt_pwd(stored: str) -> str:
    if not stored:
        return ""
    try:
        if stored.startswith("dpapi:"):
            return dpapi_decrypt(base64.b64decode(stored[6:])).decode("utf-8")
        if stored.startswith("plain:"):
            return base64.b64decode(stored[6:]).decode("utf-8")
    except Exception:
        return ""
    return ""


# --------------------------------------------------------------------------- #
#  Profiles
# --------------------------------------------------------------------------- #
def load_profiles():
    try:
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (OSError, ValueError):
        return {}


def save_profiles(profiles):
    os.makedirs(PROFILE_DIR, exist_ok=True)
    tmp = PROFILE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=2)
    os.replace(tmp, PROFILE_FILE)


# --------------------------------------------------------------------------- #
#  Wake-on-LAN + LAN scan
# --------------------------------------------------------------------------- #
def wake_on_lan(mac, broadcast="255.255.255.255", port=9, repeats=3):
    clean = mac.replace(":", "").replace("-", "").replace(".", "").replace(" ", "")
    if len(clean) != 12 or any(c not in "0123456789abcdefABCDEF" for c in clean):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    payload = bytes.fromhex("ff" * 6 + clean.lower() * 16)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        for _ in range(repeats):
            s.sendto(payload, (broadcast, port))
            time.sleep(0.1)
    finally:
        s.close()


def local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "192.168.1.1"
    finally:
        s.close()
    return ".".join(ip.split(".")[:3])


def scan_lan(subnet, timeout=0.35):
    found = []
    lk = threading.Lock()

    def probe(i):
        ip = f"{subnet}.{i}"
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((ip, 445))
            with lk:
                found.append(ip)
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=128) as ex:
        list(ex.map(probe, range(1, 255)))
    return sorted(found, key=lambda x: int(x.rsplit(".", 1)[1]))


# --------------------------------------------------------------------------- #
#  Robocopy engine
# --------------------------------------------------------------------------- #
def robocopy_push(src, dst_unc, streams=32, resume=True,
                  skip_unchanged=False, mirror=False):
    args = [
        "robocopy", src, dst_unc,
        "/E",
        f"/MT:{streams}",
        "/R:2", "/W:1",
        "/NP", "/NDL", "/NC", "/NS", "/NJH", "/NJS",
        "/COPY:DAT",
    ]
    if resume:
        args.append("/Z")
    if mirror:
        args.append("/MIR")
    elif skip_unchanged:
        args.append("/XO")             # exclude older files
    r = run_hidden(args, timeout=None)
    # Robocopy 0..7 are success bit-flags; >=8 is a real failure.
    if r.returncode >= 8:
        raise RuntimeError(
            f"robocopy failed (code {r.returncode})\n{(r.stdout or '')[-1500:]}"
        )
    return r.stdout or ""


# --------------------------------------------------------------------------- #
#  Stats
# --------------------------------------------------------------------------- #
class Stats:
    __slots__ = ("total", "done", "files_total", "files_done", "t0", "_lk")

    def __init__(self, total, files_total):
        self.total = total
        self.done = 0
        self.files_total = files_total
        self.files_done = 0
        self.t0 = time.time()
        self._lk = threading.Lock()

    def add(self, n):
        with self._lk:
            self.done += n

    def file_done(self):
        with self._lk:
            self.files_done += 1

    def snapshot(self):
        with self._lk:
            return self.done, self.files_done


def collect(src):
    """-> ([(abs_src, rel_dest), ...], total_bytes)"""
    if os.path.isfile(src):
        return [(src, os.path.basename(src))], os.path.getsize(src)

    base = src.rstrip("\\/")
    items, total = [], 0
    for dirpath, _dirnames, filenames in os.walk(base):
        rel_dir = os.path.relpath(dirpath, base)
        if rel_dir == ".":
            rel_dir = ""
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                total += os.path.getsize(full)
            except OSError:
                pass
            items.append((full, os.path.join(rel_dir, name) if rel_dir else name))
    return items, total


# --------------------------------------------------------------------------- #
#  Copy engine (resume + retry + verify + rate-limit)
# --------------------------------------------------------------------------- #
def _resume_offset(tmp, src_size):
    """Where to resume from within tmp, or 0 to start fresh."""
    if not os.path.exists(tmp):
        return 0
    n = os.path.getsize(tmp)
    if n > src_size:
        try:
            os.remove(tmp)
        except OSError:
            pass
        return 0
    return n


def copy_one(src, dst, stats, cancel, verify_mode="size",
             resume=True, limiter=None, retries=3):
    """Copy src -> dst with resume, retry, verify, and optional rate-limit.

    verify_mode: "off" | "size" | "sha256"
    On Cancelled or transient errors the .part file is KEPT so a later
    run can resume. It is removed only when verify proves corruption.
    """
    parent = os.path.dirname(dst)
    if parent:
        os.makedirs(parent, exist_ok=True)

    tmp = dst + ".part"
    src_size = os.path.getsize(src)
    counted = 0  # bytes already reported to stats in this call

    for attempt in range(retries + 1):
        if cancel.is_set():
            raise Cancelled()
        try:
            offset = _resume_offset(tmp, src_size) if resume else 0
            if offset > counted:
                stats.add(offset - counted)
                counted = offset

            if offset < src_size:
                mode = "ab" if offset else "wb"
                with open(src, "rb", buffering=0) as fi, \
                     open(tmp, mode, buffering=0) as fo:
                    if offset:
                        fi.seek(offset)
                    while True:
                        if cancel.is_set():
                            raise Cancelled()
                        buf = fi.read(CHUNK)
                        if not buf:
                            break
                        fo.write(buf)
                        stats.add(len(buf))
                        if limiter is not None:
                            limiter.consume(len(buf))

            # ---- verify ------------------------------------------------
            if verify_mode == "size":
                if os.path.getsize(tmp) != src_size:
                    raise IOError("size mismatch after transfer")
            elif verify_mode == "sha256":
                if sha256_file(tmp, cancel) != sha256_file(src, cancel):
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
                    raise IOError("sha256 mismatch after transfer")

            os.replace(tmp, dst)
            try:
                shutil.copystat(src, dst)
            except OSError:
                pass
            stats.file_done()
            return

        except Cancelled:
            raise
        except Exception:
            if attempt == retries:
                raise
            # Exponential backoff, capped at 8 s.
            for _ in range(int(min(2 ** attempt, 8) * 10)):
                if cancel.is_set():
                    raise Cancelled()
                time.sleep(0.1)


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  \u2014  Sender")
        self.geometry("960x760")
        self.minsize(880, 680)

        self.msgq = queue.Queue()
        self.cancel_evt = threading.Event()
        self.busy = False
        self.stats = None
        self.connected_unc = None

        self._build_ui()
        self._refresh_profiles()
        self.after(100, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = dict(padx=6, pady=4)
        root = ttk.Frame(self, padding=10)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(7, weight=1)

        # ---- Profiles bar -----------------------------------------------
        pbar = ttk.Frame(root)
        pbar.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        ttk.Label(pbar, text="Profile:").pack(side="left", padx=(0, 4))
        self.profile_var = tk.StringVar()
        self.profile_combo = ttk.Combobox(pbar, textvariable=self.profile_var, width=26)
        self.profile_combo.pack(side="left")
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self.on_profile_load())

        ttk.Button(pbar, text="Save\u2026", width=8,
                   command=self.on_profile_save).pack(side="left", padx=(6, 0))
        ttk.Button(pbar, text="Delete", width=8,
                   command=self.on_profile_delete).pack(side="left", padx=(4, 0))
        ttk.Button(pbar, text="Refresh", width=8,
                   command=self._refresh_profiles).pack(side="left", padx=(4, 0))

        # ---- Target ------------------------------------------------------
        tf = ttk.LabelFrame(root, text="1 \u00b7 Target machine")
        tf.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        tf.columnconfigure(1, weight=3)
        tf.columnconfigure(4, weight=2)

        ttk.Label(tf, text="IP / hostname:").grid(row=0, column=0, sticky="w", **pad)
        self.host_var = tk.StringVar(value="192.168.1.50")
        ttk.Entry(tf, textvariable=self.host_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(tf, text="Detect", width=9, command=self.on_detect).grid(row=0, column=2, **pad)

        ttk.Label(tf, text="Share:").grid(row=0, column=3, sticky="w", **pad)
        self.share_var = tk.StringVar(value="C$")
        ttk.Combobox(tf, textvariable=self.share_var, width=12,
                     values=["C$", "D$", "E$", "ADMIN$", "Users", "Public"]
                     ).grid(row=0, column=4, sticky="w", **pad)

        ttk.Label(tf, text="Username:").grid(row=1, column=0, sticky="w", **pad)
        self.user_var = tk.StringVar()
        ttk.Entry(tf, textvariable=self.user_var).grid(row=1, column=1, sticky="ew", **pad)

        ttk.Label(tf, text="Password:").grid(row=1, column=3, sticky="w", **pad)
        self.pass_var = tk.StringVar()
        ttk.Entry(tf, textvariable=self.pass_var, show="\u25cf"
                  ).grid(row=1, column=4, sticky="ew", **pad)

        ttk.Label(tf, foreground="#666",
                  text="Account must be a local administrator on the target (required for C$)."
                  ).grid(row=2, column=0, columnspan=5, sticky="w", padx=6)

        ttk.Label(tf, text="MAC (Wake-on-LAN):").grid(row=3, column=0, sticky="w", **pad)
        self.mac_var = tk.StringVar()
        ttk.Entry(tf, textvariable=self.mac_var).grid(row=3, column=1, sticky="ew", **pad)
        ttk.Button(tf, text="Wake", width=9, command=self.on_wake
                   ).grid(row=3, column=2, **pad)

        # ---- Source ------------------------------------------------------
        sf = ttk.LabelFrame(root, text="2 \u00b7 Source (this PC)")
        sf.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        sf.columnconfigure(0, weight=1)

        self.src_var = tk.StringVar()
        ttk.Entry(sf, textvariable=self.src_var).grid(row=0, column=0, sticky="ew", **pad)
        ttk.Button(sf, text="File\u2026", width=9,
                   command=lambda: self._pick_file()).grid(row=0, column=1, **pad)
        ttk.Button(sf, text="Folder\u2026", width=10,
                   command=lambda: self._pick_dir()).grid(row=0, column=2, **pad)

        # ---- Destination -------------------------------------------------
        df = ttk.LabelFrame(root, text="3 \u00b7 Destination folder on the target")
        df.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        df.columnconfigure(0, weight=1)

        self.dst_var = tk.StringVar(value=r"C:\Users\Public\Transfer")
        ttk.Entry(df, textvariable=self.dst_var).grid(row=0, column=0, sticky="ew", **pad)
        ttk.Button(df, text="Browse\u2026", width=10,
                   command=self.on_browse_remote).grid(row=0, column=1, **pad)

        # ---- Options -----------------------------------------------------
        of = ttk.Frame(root)
        of.grid(row=4, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(of, text="Streams:").grid(row=0, column=0, sticky="w", padx=(6, 4))
        self.threads_var = tk.IntVar(value=8)
        ttk.Spinbox(of, from_=1, to=32, width=4, textvariable=self.threads_var
                    ).grid(row=0, column=1, sticky="w")

        ttk.Label(of, text="Limit MB/s:").grid(row=0, column=2, sticky="w", padx=(16, 4))
        self.limit_var = tk.DoubleVar(value=0.0)
        ttk.Spinbox(of, from_=0, to=10000, increment=10, width=6,
                    textvariable=self.limit_var).grid(row=0, column=3, sticky="w")

        ttk.Label(of, text="Verify:").grid(row=0, column=4, sticky="w", padx=(16, 4))
        self.verify_var = tk.StringVar(value="size")
        ttk.Combobox(of, textvariable=self.verify_var, width=8, state="readonly",
                     values=["off", "size", "sha256"]).grid(row=0, column=5, sticky="w")

        ttk.Label(of, text="Engine:").grid(row=0, column=6, sticky="w", padx=(16, 4))
        self.engine_var = tk.StringVar(value="python")
        ttk.Combobox(of, textvariable=self.engine_var, width=10, state="readonly",
                     values=["python", "robocopy"]).grid(row=0, column=7, sticky="w")

        self.resume_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(of, text="Resume partial files", variable=self.resume_var
                        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.skip_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(of, text="Skip unchanged", variable=self.skip_var
                        ).grid(row=1, column=2, columnspan=2, sticky="w", pady=(4, 0))

        self.skip_policy_var = tk.StringVar(value="size+mtime")
        ttk.Combobox(of, textvariable=self.skip_policy_var, width=12, state="readonly",
                     values=["size", "size+mtime", "sha256"]
                     ).grid(row=1, column=4, columnspan=2, sticky="w", pady=(4, 0))

        # ---- Buttons -----------------------------------------------------
        bf = ttk.Frame(root)
        bf.grid(row=5, column=0, sticky="ew", pady=(0, 8))

        self.btn_test = ttk.Button(bf, text="Test connection", command=self.on_test)
        self.btn_test.pack(side="left", padx=(0, 6))
        self.btn_conn = ttk.Button(bf, text="Connect", command=self.on_connect)
        self.btn_conn.pack(side="left", padx=(0, 6))

        self.btn_start = ttk.Button(bf, text="\u25b6  Start transfer", command=self.on_start)
        self.btn_start.pack(side="left", padx=(20, 6))
        self.btn_cancel = ttk.Button(bf, text="Cancel", command=self.on_cancel, state="disabled")
        self.btn_cancel.pack(side="left")

        # ---- Progress ----------------------------------------------------
        pf = ttk.Frame(root)
        pf.grid(row=6, column=0, sticky="ew")
        pf.columnconfigure(0, weight=1)

        self.bar = ttk.Progressbar(pf, maximum=1000, mode="determinate")
        self.bar.grid(row=0, column=0, sticky="ew", padx=6, pady=(4, 2))

        self.pct_var = tk.StringVar(value="Idle")
        ttk.Label(pf, textvariable=self.pct_var, font=("Consolas", 9)
                  ).grid(row=1, column=0, sticky="w", padx=6)

        # ---- Log ---------------------------------------------------------
        lf = ttk.LabelFrame(root, text="Log")
        lf.grid(row=7, column=0, sticky="nsew", pady=(8, 0))
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self.logbox = ScrolledText(lf, height=10, state="disabled",
                                   font=("Consolas", 9), wrap="none")
        self.logbox.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        # ---- Menu --------------------------------------------------------
        mbar = tk.Menu(self)
        tools = tk.Menu(mbar, tearoff=0)
        tools.add_command(label="Prepare THIS PC (enable sharing + firewall)",
                          command=self.on_prepare_local)
        tools.add_command(label="Scan LAN for SMB hosts", command=self.on_scan_lan)
        tools.add_command(label="Wake target (WoL)", command=self.on_wake)
        tools.add_command(label="Disconnect SMB sessions", command=self.on_disconnect)
        tools.add_separator()
        tools.add_command(label="Exit", command=self._on_close)
        mbar.add_cascade(label="Tools", menu=tools)
        mbar.add_command(label="About", command=self.on_about)
        self.config(menu=mbar)

    # -------------------------------------------------------------- utils
    def log(self, text):
        self.msgq.put(("log", text))

    def status(self, text):
        self.msgq.put(("status", text))

    def _append_log(self, text):
        ts = time.strftime("%H:%M:%S")
        self.logbox.configure(state="normal")
        self.logbox.insert("end", f"[{ts}] {text}\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _pump(self):
        try:
            while True:
                kind, *rest = self.msgq.get_nowait()
                if kind == "log":
                    self._append_log(rest[0])
                elif kind == "status":
                    self.pct_var.set(rest[0])
                elif kind == "set_host":
                    self.host_var.set(rest[0])
                elif kind == "bar_mode":
                    mode = rest[0]
                    if mode == "indeterminate":
                        self.bar.configure(mode="indeterminate")
                        self.bar.start(15)
                    else:
                        self.bar.stop()
                        self.bar.configure(mode="determinate")
                        self.bar["value"] = 0
                elif kind == "done":
                    self._finish(*rest)
        except queue.Empty:
            pass

        st = self.stats
        if st is not None:
            done, fdone = st.snapshot()
            total = st.total or 1
            frac = min(done / total, 1.0)
            self.bar["value"] = frac * 1000
            el = max(time.time() - st.t0, 1e-6)
            speed = done / el / (1024 * 1024)
            eta = (total - done) / (done / el) if done else 0
            self.pct_var.set(
                f"{frac * 100:5.1f}%   {human(done)} / {human(total)}   "
                f"{speed:6.1f} MB/s   ETA {human_time(eta)}   "
                f"files {fdone}/{st.files_total}"
            )
        self.after(100, self._pump)

    def _set_busy(self, busy):
        self.busy = busy
        state = "disabled" if busy else "normal"
        for b in (self.btn_test, self.btn_conn, self.btn_start):
            b.configure(state=state)
        self.btn_cancel.configure(state="normal" if busy else "disabled")

    def _finish(self, ok, message):
        self._set_busy(False)
        if ok:
            self.log("DONE. " + message)
            messagebox.showinfo(APP_NAME, message)
        else:
            if message == "__CANCELLED__":
                self.log("Cancelled by user.")
                self.pct_var.set("Cancelled")
            elif message == "__SILENT__":
                pass
            else:
                self.log("ERROR: " + message)
                messagebox.showerror(APP_NAME, message)

    # ------------------------------------------------------------- pickers
    def _pick_file(self):
        p = filedialog.askopenfilename(title="Select file to send")
        if p:
            self.src_var.set(os.path.normpath(p))

    def _pick_dir(self):
        p = filedialog.askdirectory(title="Select folder to send")
        if p:
            self.src_var.set(os.path.normpath(p))

    def on_browse_remote(self):
        host = norm_host(self.host_var.get())
        if not host:
            messagebox.showwarning(APP_NAME, "Enter the target IP/hostname first.")
            return
        share = self.share_var.get().strip() or "C$"
        if self.connected_unc is None:
            if not self._connect_sync():
                return
        start = build_unc(host, share, self.dst_var.get()) or f"\\\\{host}\\{share}"
        try:
            p = filedialog.askdirectory(title="Pick destination folder on the target",
                                        initialdir=start)
        except Exception:
            p = None
        if p:
            p = os.path.normpath(p)
            if p.startswith("\\\\"):
                parts = p.lstrip("\\").split("\\", 2)
                if len(parts) >= 2:
                    self.host_var.set(parts[0])
                    self.share_var.set(parts[1])
                    self.dst_var.set("\\".join(parts[2:]) if len(parts) > 2 else "")
                    return
            self.dst_var.set(p)

    # ---------------------------------------------------------- profiles
    def _refresh_profiles(self):
        profs = load_profiles()
        self.profile_combo["values"] = sorted(profs.keys())

    def on_profile_save(self):
        name = simpledialog.askstring(APP_NAME, "Profile name:", parent=self)
        if not name:
            return
        name = name.strip()
        if not name:
            return
        profs = load_profiles()
        profs[name] = {
            "host": self.host_var.get(),
            "share": self.share_var.get(),
            "user": self.user_var.get(),
            "pass_enc": _encrypt_pwd(self.pass_var.get()),
            "dst": self.dst_var.get(),
            "streams": int(self.threads_var.get() or 8),
            "mac": self.mac_var.get(),
        }
        try:
            save_profiles(profs)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Could not save profile:\n{e}")
            return
        self.profile_var.set(name)
        self._refresh_profiles()
        self.log(f"Profile '{name}' saved.")

    def on_profile_load(self):
        name = self.profile_var.get().strip()
        if not name:
            return
        profs = load_profiles()
        p = profs.get(name)
        if not p:
            return
        self.host_var.set(p.get("host", ""))
        self.share_var.set(p.get("share", "C$"))
        self.user_var.set(p.get("user", ""))
        self.pass_var.set(_decrypt_pwd(p.get("pass_enc", "")))
        self.dst_var.set(p.get("dst", r"C:\Users\Public\Transfer"))
        if p.get("streams"):
            try:
                self.threads_var.set(int(p["streams"]))
            except Exception:
                pass
        self.mac_var.set(p.get("mac", ""))
        self.log(f"Profile '{name}' loaded.")

    def on_profile_delete(self):
        name = self.profile_var.get().strip()
        if not name:
            return
        if not messagebox.askyesno(APP_NAME, f"Delete profile '{name}'?"):
            return
        profs = load_profiles()
        profs.pop(name, None)
        try:
            save_profiles(profs)
        except OSError:
            pass
        self.profile_var.set("")
        self._refresh_profiles()

    # ------------------------------------------------------------- actions
    def on_detect(self):
        host = norm_host(self.host_var.get())
        if not host:
            messagebox.showwarning(APP_NAME, "Enter a target IP/hostname.")
            return
        self.log(f"Probing {host} \u2026")
        self.update_idletasks()

        def work():
            ping_ok, smb_ok = probe_host(host)
            self.log(f"Ping: {'OK' if ping_ok else 'no reply'} | "
                     f"TCP 445 (SMB): {'OPEN' if smb_ok else 'CLOSED/blocked'}")
            if smb_ok:
                self.status("Target reachable \u2014 SMB port open.")
            elif ping_ok:
                self.status("Host up, but SMB port 445 is closed "
                            "(enable File & Printer Sharing on the target).")
            else:
                self.status("Host not reachable.")
        threading.Thread(target=work, daemon=True).start()

    def on_test(self):
        """Probe reachability AND try to actually mount the share."""
        if self.busy:
            return
        host = norm_host(self.host_var.get())
        if not host:
            messagebox.showwarning(APP_NAME, "Enter a target IP/hostname.")
            return

        share = self.share_var.get().strip() or "C$"
        user = self.user_var.get().strip()
        pwd = self.pass_var.get()

        self._set_busy(True)
        self.status("Testing connection\u2026")
        self.log(f"Testing {host} (share {share})\u2026")

        def work():
            ping_ok, smb_ok = probe_host(host)
            self.log(f"Ping: {'OK' if ping_ok else 'no reply'} | "
                     f"TCP 445 (SMB): {'OPEN' if smb_ok else 'CLOSED/blocked'}")

            if not smb_ok:
                self.msgq.put(("done", False,
                    "SMB port 445 not reachable.\n\n"
                    "On the target PC:\n"
                    "  \u2022 Enable 'File and Printer Sharing'\n"
                    "  \u2022 Allow File and Printer Sharing through Windows Firewall\n"
                    "  \u2022 Make sure both PCs are on the same subnet"))
                return

            try:
                unc = smb_connect(host, share, user, pwd, self.log)
                smb_disconnect(unc)
                self.msgq.put(("done", True,
                    f"Target OK.\n\n{unc} authenticated successfully."))
            except Exception as e:
                self.msgq.put(("done", False, str(e)))

        threading.Thread(target=work, daemon=True).start()

    def on_wake(self):
        mac = self.mac_var.get().strip()
        if not mac:
            messagebox.showwarning(APP_NAME, "Enter the target's MAC address first.")
            return
        host = norm_host(self.host_var.get())
        broadcast = "255.255.255.255"
        if host and host.count(".") == 3:
            broadcast = host.rsplit(".", 1)[0] + ".255"

        def work():
            try:
                wake_on_lan(mac, broadcast=broadcast)
                self.log(f"WoL magic packet sent to {mac} via {broadcast}")
            except Exception as e:
                self.log(f"WoL failed: {e}")
        threading.Thread(target=work, daemon=True).start()

    def on_scan_lan(self):
        subnet = local_subnet()
        self.log(f"Scanning {subnet}.1-254 for SMB hosts\u2026")
        self.status("Scanning LAN\u2026")

        def work():
            hosts = scan_lan(subnet)
            if not hosts:
                self.log("No SMB hosts found.")
                self.status("No SMB hosts found.")
                return
            self.log(f"Found {len(hosts)} SMB host(s):")
            for h in hosts:
                self.log(f"  \u2022 {h}")
            self.msgq.put(("set_host", hosts[0]))
            self.status(f"Found {len(hosts)} host(s) \u2014 filled in {hosts[0]}")
        threading.Thread(target=work, daemon=True).start()

    def _connect_sync(self):
        """Blocking connect (used by Browse). Returns True on success."""
        host = norm_host(self.host_var.get())
        share = self.share_var.get().strip() or "C$"
        user = self.user_var.get().strip()
        pwd = self.pass_var.get()
        if not host:
            messagebox.showwarning(APP_NAME, "Enter a target IP/hostname.")
            return False
        try:
            self.connected_unc = smb_connect(host, share, user, pwd, self.log)
            return True
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))
            return False

    def on_connect(self):
        if self.busy:
            return
        self._set_busy(True)
        self.status("Connecting\u2026")

        def work():
            ok = self._connect_sync()
            self.msgq.put(("done", True if ok else False,
                           "Connected." if ok else "__SILENT__"))
        threading.Thread(target=work, daemon=True).start()

    def on_disconnect(self):
        if self.connected_unc:
            smb_disconnect(self.connected_unc)
            self.log(f"Disconnected {self.connected_unc}")
            self.connected_unc = None
        else:
            self.log("No active session.")

    def on_prepare_local(self):
        """Enable sharing + firewall on THIS machine (UAC prompt)."""
        script = (
            'netsh advfirewall firewall set rule group="File and Printer Sharing" '
            'new enable=Yes & '
            'netsh advfirewall firewall set rule group="Network Discovery" '
            'new enable=Yes & '
            'sc config LanmanServer start= auto & net start LanmanServer'
        )
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "cmd.exe", f'/k {script}', None, 1)
            self.log("Elevation requested \u2014 follow the UAC prompt.")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Could not elevate:\n{e}")

    def on_about(self):
        messagebox.showinfo(
            APP_NAME,
            f"{APP_NAME}\n\n"
            "Push files over Ethernet to any Windows PC using SMB.\n"
            "Only this side runs software.\n\n"
            "Resume, retry, delta-sync, SHA-256 verify, rate limit,\n"
            "profiles with DPAPI-encrypted passwords, WoL, LAN scan,\n"
            "and a robocopy engine fallback.\n\n"
            "Tip: gigabit + 8 streams \u2248 110 MB/s."
        )

    def on_cancel(self):
        self.cancel_evt.set()
        self.log("Cancelling\u2026")

    def _on_close(self):
        if self.busy:
            if not messagebox.askyesno(APP_NAME, "A transfer is running. Quit anyway?"):
                return
            self.cancel_evt.set()
        if self.connected_unc:
            smb_disconnect(self.connected_unc)
        self.destroy()

    # ------------------------------------------------------------- transfer
    def on_start(self):
        if self.busy:
            return

        cfg = {
            "host": norm_host(self.host_var.get()),
            "share": self.share_var.get().strip() or "C$",
            "user": self.user_var.get().strip(),
            "pwd": self.pass_var.get(),
            "src": self.src_var.get().strip().strip('"'),
            "dst_rel": self.dst_var.get().strip().strip('"'),
            "workers": max(1, min(32, int(self.threads_var.get() or 8))),
            "verify_mode": (self.verify_var.get() or "size").strip(),
            "resume": bool(self.resume_var.get()),
            "skip": bool(self.skip_var.get()),
            "skip_policy": self.skip_policy_var.get() or "size+mtime",
            "limit_mbps": float(self.limit_var.get() or 0),
            "engine": (self.engine_var.get() or "python").strip(),
        }

        if not cfg["host"]:
            messagebox.showwarning(APP_NAME, "Enter the target IP/hostname.")
            return
        if not cfg["src"] or not os.path.exists(cfg["src"]):
            messagebox.showwarning(APP_NAME, "Select a valid source file or folder.")
            return
        if not cfg["dst_rel"]:
            messagebox.showwarning(APP_NAME, "Enter a destination folder on the target.")
            return

        self.cancel_evt.clear()
        self.stats = None
        self.bar.stop()
        self.bar.configure(mode="determinate")
        self.bar["value"] = 0
        self._set_busy(True)
        self.status("Starting\u2026")
        self.log("\u2500" * 62)
        self.log(f"Source      : {cfg['src']}")
        self.log(f"Destination : \\\\{cfg['host']}\\{cfg['share']}\\"
                 f"{cfg['dst_rel'].lstrip(chr(92))}")
        self.log(f"Engine      : {cfg['engine']}   Streams: {cfg['workers']}   "
                 f"Verify: {cfg['verify_mode']}")
        self.log(f"Resume      : {cfg['resume']}   "
                 f"Skip-unchanged: {cfg['skip']} ({cfg['skip_policy']})   "
                 f"Limit: {cfg['limit_mbps']} MB/s")

        threading.Thread(target=self._transfer_worker,
                         args=(cfg,), daemon=True).start()

    def _transfer_worker(self, cfg):
        try:
            if self.connected_unc:
                unc = self.connected_unc
            else:
                unc = smb_connect(cfg["host"], cfg["share"],
                                  cfg["user"], cfg["pwd"], self.log)
                self.connected_unc = unc

            dst_root = build_unc(cfg["host"], cfg["share"], cfg["dst_rel"])
            self.log(f"Creating {dst_root}")
            os.makedirs(dst_root, exist_ok=True)

            if cfg["engine"] == "robocopy" and os.path.isdir(cfg["src"]):
                self._run_robocopy(cfg, dst_root)
            else:
                self._run_python(cfg, dst_root)

        except Exception as e:
            self.msgq.put(("done", False, str(e)))

    # ---- Python engine ------------------------------------------------
    def _run_python(self, cfg, dst_root):
        self.log("Scanning source\u2026")
        items, total = collect(cfg["src"])
        if not items:
            raise RuntimeError("Nothing to transfer (source is empty).")
        self.log(f"{len(items)} file(s), {human(total)} total.")

        st = Stats(total, len(items))
        self.stats = st

        limiter = (RateLimiter(int(cfg["limit_mbps"] * 1024 * 1024))
                   if cfg["limit_mbps"] > 0 else None)

        errors = []

        def job(item):
            abs_src, rel = item
            target = os.path.join(dst_root, rel)
            try:
                if cfg["skip"] and unchanged(abs_src, target,
                                             cfg["skip_policy"], self.cancel_evt):
                    st.add(os.path.getsize(abs_src))
                    st.file_done()
                    return
                copy_one(
                    abs_src, target, st, self.cancel_evt,
                    verify_mode=cfg["verify_mode"],
                    resume=cfg["resume"],
                    limiter=limiter,
                )
            except Cancelled:
                raise
            except Exception as e:
                errors.append(f"{rel}: {e}")

        with ThreadPoolExecutor(max_workers=cfg["workers"]) as pool:
            futures = [pool.submit(job, it) for it in items]
            for f in futures:
                if self.cancel_evt.is_set():
                    break
                try:
                    f.result()
                except Cancelled:
                    break
                except Exception as e:
                    errors.append(str(e))

        if self.cancel_evt.is_set():
            self.msgq.put(("done", False, "__CANCELLED__"))
            return

        done, fdone = st.snapshot()
        el = max(time.time() - st.t0, 1e-6)
        avg = done / el / (1024 * 1024)

        if errors:
            detail = "\n".join(errors[:12])
            more = "" if len(errors) <= 12 else f"\n\u2026 and {len(errors)-12} more"
            self.msgq.put(("done", False,
                           f"{len(errors)} file(s) failed:\n\n{detail}{more}"))
            return

        self.msgq.put((
            "done", True,
            f"Transferred {fdone} file(s), {human(done)} in "
            f"{human_time(el)}  (avg {avg:.1f} MB/s).",
        ))

    # ---- Robocopy engine ----------------------------------------------
    def _run_robocopy(self, cfg, dst_root):
        self.log("Launching robocopy (indeterminate progress; cancel is best-effort)\u2026")
        self.msgq.put(("bar_mode", "indeterminate"))
        try:
            out = robocopy_push(
                cfg["src"], dst_root,
                streams=cfg["workers"],
                resume=cfg["resume"],
                skip_unchanged=cfg["skip"],
                mirror=False,
            )
        finally:
            self.msgq.put(("bar_mode", "determinate"))

        if out:
            for line in out.strip().splitlines()[-25:]:
                self.log(line)

        if self.cancel_evt.is_set():
            self.msgq.put(("done", False, "__CANCELLED__"))
            return
        self.msgq.put(("done", True, "Robocopy completed successfully."))


# --------------------------------------------------------------------------- #
#  CLI mode
# --------------------------------------------------------------------------- #
def _cli_main(argv):
    import argparse
    ap = argparse.ArgumentParser(
        prog="eth2eth",
        description="ETH Transfer Toolkit \u2014 CLI (no GUI).",
    )
    ap.add_argument("--host", required=True)
    ap.add_argument("--share", default="C$")
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--streams", type=int, default=8)
    ap.add_argument("--limit-mbps", type=float, default=0.0)
    ap.add_argument("--verify", choices=["off", "size", "sha256"], default="size")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--skip-unchanged", action="store_true")
    ap.add_argument("--engine", choices=["python", "robocopy"], default="python")
    a = ap.parse_args(argv)

    def logprint(s):
        print(s, flush=True)

    logprint(f"Connecting to \\\\{a.host}\\{a.share}\u2026")
    unc = smb_connect(a.host, a.share, a.user, a.password, logprint)
    try:
        dst_root = build_unc(a.host, a.share, a.dst)
        os.makedirs(dst_root, exist_ok=True)

        if a.engine == "robocopy" and os.path.isdir(a.src):
            robocopy_push(a.src, dst_root, streams=a.streams,
                          resume=not a.no_resume,
                          skip_unchanged=a.skip_unchanged)
            print("Robocopy done.")
            return 0

        items, total = collect(a.src)
        logprint(f"{len(items)} file(s), {human(total)} total.")
        st = Stats(total, len(items))
        cancel = threading.Event()
        limiter = (RateLimiter(int(a.limit_mbps * 1024 * 1024))
                   if a.limit_mbps > 0 else None)
        errors = []

        def job(item):
            s, rel = item
            t = os.path.join(dst_root, rel)
            try:
                if a.skip_unchanged and unchanged(s, t):
                    st.add(os.path.getsize(s))
                    st.file_done()
                    return
                copy_one(s, t, st, cancel,
                         verify_mode=a.verify,
                         resume=not a.no_resume,
                         limiter=limiter)
            except Exception as e:
                errors.append(f"{rel}: {e}")

        with ThreadPoolExecutor(max_workers=a.streams) as ex:
            list(ex.map(job, items))

        done, fdone = st.snapshot()
        print(f"Done: {fdone} file(s), {human(done)}")
        if errors:
            print(f"{len(errors)} error(s):")
            for e in errors[:20]:
                print("  ", e)
            return 2
        return 0
    finally:
        smb_disconnect(unc)


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    if not IS_WIN:
        print("This tool targets Windows.")
        sys.exit(1)

    # CLI mode if any known flag is present; otherwise GUI.
    _CLI_FLAGS = {"--host", "--src", "--dst", "--user", "--password",
                  "--share", "--help", "-h", "--streams", "--verify",
                  "--engine", "--no-resume", "--skip-unchanged", "--limit-mbps"}
    argv = sys.argv[1:]
    if any((a in _CLI_FLAGS) or a.startswith("--host=") or a.startswith("--src=")
           for a in argv):
        sys.exit(_cli_main(argv))

    App().mainloop()
