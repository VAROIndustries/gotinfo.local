# gotinfo.local

[![VARØ Industries](https://img.shields.io/badge/VAR%C3%98-Industries-c8883e?style=flat-square)](https://varo.industries)

> **What's using my network?** A console network monitor for Windows, a sibling of [HTopWin](https://github.com/VAROIndustries/HTopWin). It's the local companion to [gotinfo.net](https://gotinfo.net).

Built with [Textual](https://textual.textualize.io/) + [psutil](https://psutil.readthedocs.io/). Per-process bytes come from ETW (`Microsoft-Windows-Kernel-Network`) through plain ctypes, with no other dependencies.

## Features
- **NIC down/up**: live rate, total and peak since launch, with 2-minute sparklines
- **Processes tab**: download and upload rate per process, totals since launch, and open connection count
- **Details** (Enter): exe, command line, user, start time, memory, and every remote endpoint with reverse DNS, state and rx/tx
- **Ports tab**: every open TCP/UDP port (listening, bound and connected) with its owning process, rx/tx rate and totals
- Covers TCP **and UDP** (so QUIC/HTTP3 traffic shows up), IPv4 + IPv6, and connections too short-lived to appear in a poll

## Run
```
pip install -r requirements.txt
python gotinfo.py
```
**Per-process bytes need an elevated (admin) console.** Without admin you still get the NIC totals and the full port and connection list, and pressing `a` relaunches it elevated.

| Key | Action |
|---|---|
| `1` / `2` | Processes / Ports |
| `Enter` | Details for the selected process |
| `s` | Cycle sort: ↓/s, ↑/s, ↓ total, ↑ total |
| `c` | Hide/show closed ports |
| `a` | Relaunch as admin |
| `r` | Reset totals |
| `q` | Quit |

## Test
```
python gotinfo.py --selftest
python test_smoke.py
```
`python netetw.py` (elevated) runs a 10-second live capture and prints the top talkers.

## Notes
- Totals count from launch. ETW only sees traffic while the session is running.
- The trace session is named `GotInfoLocalNet`. A stale one left by a crash is stopped automatically on the next start.
- x64 Python only, because the ETW struct layout is asserted at import.
