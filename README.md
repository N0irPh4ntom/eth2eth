# eth2eth
ETH Transfer Toolkit
A tiny Python GUI that shoves files from one Windows PC to another over Ethernet using SMB. Only the sending side runs software — the other machine just needs normal Windows file sharing turned on, which every Windows install already has.

I got tired of plugging in USB drives or setting up shared folders just to move a few hundred GB between my desktop and my old Win7 box. This is what I ended up with. It mounts the target's admin share (C$, D$, …), copies in parallel, resumes if the link hiccups, and disconnects when it's done. No agents, no installers, no cloud.

Requirements
On the PC that runs the tool (the sender):

Windows 7 SP1 / 10 / 11

Python 3.8 or newer (from python.org — the Microsoft Store build works too, but its tkinter is occasionally broken so prefer the official installer)

That's it. No pip install. tkinter ships with Python.

On the PC receiving the files (the target):

Any Windows, any version. Literally nothing to install.

File & Printer Sharing enabled

Port 445 open in Windows Firewall

The account you'll authenticate with must be a local administrator (required for the administrative shares C$, D$, ADMIN$)

Same subnet as the sender

That's the whole dependency list.

Features
Transfer engine

Raw 4 MB unbuffered chunks — no Python-level buffering overhead

Parallel streams (8 saturates a Gigabit link; crank to 32 for lots of small files)

Atomic finalize — files are written as .part then renamed, so you never see a half-written file at the destination

Timestamps preserved

Reliability

Resume — if a transfer is cancelled or the network drops, .part files are kept. Next run picks up at the exact byte offset.

Retry with backoff — 3 attempts per file, 1 s → 2 s → 4 s. Survives transient SMB hiccups that used to kill the whole run.

Verification — size (default), SHA-256 (paranoid), or off.

Delta sync

Skip files that already exist with a matching size, size + modification time, or full SHA-256 hash.

Second runs against a mostly-unchanged tree finish in seconds.

Quality of life

Saved profiles — host, share, credentials, destination, stream count, MAC. Passwords are encrypted with Windows DPAPI (per-user, per-machine), so a stolen profiles.json is useless anywhere else.

Wake-on-LAN — send a magic packet to the target before connecting.

LAN scanner — sweeps the /24 for anything listening on 445 and drops the first hit in the host field.

Robocopy engine — optional second backend that shells out to Windows' own robocopy /MT /Z. Slower to start, more battle-hardened for edge cases (long paths, ACLs, reparse points).

Bandwidth limiter — global token bucket in MB/s. Set to 0 for full speed.

Also

Live progress bar with MB/s, ETA, and file counts

Dark-ish log pane that timestamps everything

CLI mode — drop a few flags on the command line and it runs headless. Pair it with Task Scheduler and you've got nightly backups to your NAS.

Usage
GUI (the normal way)
text
python eth2eth.py
Fill in the target — IP/hostname, share (C$ is fine), admin username, password. If it's a Microsoft-account login, use MicrosoftAccount\you@outlook.com as the username, not the plain email.

Test connection — pings, checks port 445, then attempts a real mount. If the log shows authenticated successfully you're good. Otherwise it tells you exactly what's wrong (wrong password, non-admin account, firewall, wrong subnet).

Pick your source — a file or a whole folder tree.

Pick the destination — a path on the target like C:\Users\Public\Transfer. The Browse button opens a remote folder picker over SMB once you're connected.

Hit Start transfer. Watch the progress bar. Walk away.

If the target is off but has WoL enabled, hit the Wake button first.

CLI
text
python eth2eth.py ^
  --host 192.168.1.50 ^
  --share D$ ^
  --user Administrator ^
  --password hunter2 ^
  --src "D:\Photos" ^
  --dst "Backups\Photos" ^
  --streams 8 ^
  --verify size ^
  --skip-unchanged
Any of --host, --src, --dst, etc. on the command line triggers CLI mode. No flags → GUI.

Run python eth2eth.py --help for the full list.

Task Scheduler example (nightly incremental backup):

text
Program:  python.exe
Args:     C:\tools\eth2eth.py --host 192.168.1.50 --share D$ --user Administrator --password hunter2 --src "D:\Work" --dst "Backups\Work" --skip-unchanged --streams 16
Start in: C:\tools
Preparing the target (one time, ~2 minutes)
On the receiving PC, in an admin Command Prompt:

bat
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
Then make sure the account you'll log in with is a local admin:

Win 7 / Pro: lusrmgr.msc → Users → your account → Member Of → add Administrators

Win 10/11 Home: Settings → Accounts → Other users → select user → Change account type → Administrator

Get the IP with ipconfig. Done.

There's a menu item in the tool — Tools → Prepare THIS PC — that does the firewall part on the sender if you ever want to transfer in the other direction.

Performance
Real-world numbers on a flat gigabit switch, single 30 GB folder of mixed files, 8 streams:

Setup	Throughput
Win11 → Win11, NVMe both ends	~112 MB/s (line rate)
Win11 → Win7 SP1, HDD target	~85 MB/s (disk-bound)
Win11 → Win11 over Wi-Fi 6	~50 MB/s
Same, --limit-mbps 50	49.6 MB/s (limiter works)
If you're getting far less than the link's ceiling:

Check the cable with netstat -e on the sender — CRC errors mean bad wiring

Drop to 4 streams if the destination drive is spinning rust

Disable --verify sha256 and remeasure — it doubles traffic

Update the NIC driver. Windows' generic Realtek driver is genuinely bad

Common errors
Message	Meaning	Fix
System error 5	Bad credentials or account isn't admin	Check the account's group membership on the target
System error 53	Host not reachable	ping it; check subnet and cables
System error 67	Share doesn't exist	Use C$ / D$ / ADMIN$, or create a normal share
System error 1219	Conflicting session to the same host	net use * /delete /y then retry
SMB port 445 not reachable	Firewall on target	Run the netsh commands above on the target
Fails with a Microsoft account	Wrong username format	Use MicrosoftAccount\you@outlook.com
The Tools → Disconnect SMB sessions menu item clears mounted shares if Windows gets confused after a failed transfer.

Known limitations
The C$ / D$ admin shares require admin rights on the target. If you can't grant that, create a normal share with write permissions and put its name in the Share field instead.

Robocopy engine only handles directories, not single files. If you pick a file with robocopy selected, it silently falls back to the Python engine.

The rate limiter throttles the aggregate, not per-stream. With 8 streams at 100 MB/s total limit, each stream gets ~12.5 MB/s.

.part resume relies on the target not rewriting the file between runs. If someone else touches the destination, delete the .part and start fresh.

No progress detail during robocopy transfers (robocopy doesn't emit machine-readable progress). The bar goes indeterminate; the log shows the tail of robocopy's own output.

Why not just use SMB directly?
You can. Map the share, robocopy /MT /Z from the command line, done. That's genuinely fine if you enjoy typing UNC paths.

This exists because:

Credentials in the Windows Credential Manager get stale and are fiddly to reset

robocopy has terrible defaults for modern usage (single-threaded, no resumption)

Sometimes you just want a button

It's ~1000 lines of Python. Read it, fork it, strip out the parts you don't want.

