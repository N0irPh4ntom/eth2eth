# ETH 2 ETH

A small Python GUI for pushing files between two Windows PCs over Ethernet using SMB. Only the sender runs software — the target just needs normal Windows file sharing enabled, which it already has by default.

No agents. No cloud. No USB drives.

---

## Requirements

**Sender PC (runs the tool):**
- Windows 7 SP1 / 10 / 11
- Python 3.8+ (from [python.org](https://www.python.org/downloads/) — tkinter is bundled, no `pip install` needed)

**Target PC (receives files):**
- Any Windows version
- File & Printer Sharing enabled
- Port 445 open in the firewall
- The login account must be a **local administrator** (required for the `C$` / `D$` admin shares)
- Same subnet as the sender

---

## Features

- **Parallel transfer** — 8 streams saturates Gigabit, tunable up to 32
- **Resume** — cancelled or dropped transfers pick up where they left off
- **Retry with backoff** — survives transient SMB hiccups
- **Verify** — size (default), SHA-256, or off
- **Delta sync** — skip unchanged files on repeat runs
- **Bandwidth limiter** — cap throughput in MB/s
- **Saved profiles** — passwords encrypted with Windows DPAPI
- **Wake-on-LAN** — boot the target before connecting
- **LAN scanner** — find SMB hosts on your subnet
- **Robocopy engine** — optional fallback to Windows' own robocopy
- **CLI mode** — run headless, pair with Task Scheduler

---

## Usage

### GUI

```bash
python eth2eth.py
Enter the target's IP, share (C$ is fine), admin username, and password

Microsoft account? Use MicrosoftAccount\you@outlook.com

Click Test connection

Pick a source file or folder

Set the destination path on the target

Hit ▶ Start transfer

CLI
bash
python eth2eth.py --host 192.168.1.50 --share D$ --user Administrator \
                  --password hunter2 --src "D:\Photos" --dst "Backups\Photos" \
                  --streams 8 --skip-unchanged
Run python eth2eth.py --help for all options.

Prepare the target (one-time)
On the receiving PC, in an admin Command Prompt:

bat
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
Make sure the account you'll authenticate with is a local admin:

Win 7 / Pro: lusrmgr.msc → Users → your account → Member Of → add Administrators

Win 10/11 Home: Settings → Accounts → Other users → select user → Change account type → Administrator

Then run ipconfig to note the IP. Done.

Performance
On a flat gigabit switch, ~30 GB of mixed files, 8 streams:

Setup	Speed
Win11 → Win11, NVMe	~112 MB/s (line rate)
Win11 → Win7, HDD	~85 MB/s
Wi-Fi 6	~50 MB/s
If it's slow: check the cable, drop to 4 streams for spinning disks, disable SHA-256 verify, update the NIC driver.

Common errors
Error	Fix
System error 5	Account isn't admin on the target
System error 53	Host unreachable — check subnet / cables
System error 67	Share doesn't exist — use C$ / D$
System error 1219	net use * /delete /y then retry
SMB port 445 not reachable	Firewall on target — run the netsh commands above
