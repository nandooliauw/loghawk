#!/usr/bin/env python3
"""Generate the sample logs committed in this repo.

These are SYNTHETIC logs written to exercise every rule. They are not captures
from a real host and contain no real addresses: all IPs are RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

    python samples/generate_samples.py
"""

from __future__ import annotations

import os

HOST = "web01"
DAY = "Nov 20"

# (time, host, pid, message)
SSHD = [
    # --- normal working-hours activity
    ("08:12:31", "Accepted password for deploy from 10.0.4.21 port 44112 ssh2"),
    ("09:05:12", "Accepted publickey for alice from 10.0.4.55 port 51220 ssh2"),
    ("10:41:09", "Accepted password for bob from 10.0.4.60 port 52890 ssh2"),
    ("13:22:40", "Accepted publickey for alice from 10.0.4.55 port 53110 ssh2"),
    ("15:47:02", "Accepted password for deploy from 10.0.4.21 port 55021 ssh2"),

    # --- 03:12 brute force against 'deploy', 8 failures then a success
    ("03:12:04", "Failed password for deploy from 203.0.113.45 port 51234 ssh2"),
    ("03:12:19", "Failed password for deploy from 203.0.113.45 port 51240 ssh2"),
    ("03:12:41", "Failed password for deploy from 203.0.113.45 port 51244 ssh2"),
    ("03:13:07", "Failed password for deploy from 203.0.113.45 port 51250 ssh2"),
    ("03:13:52", "Failed password for deploy from 203.0.113.45 port 51261 ssh2"),
    ("03:14:38", "Failed password for deploy from 203.0.113.45 port 51278 ssh2"),
    ("03:16:11", "Failed password for deploy from 203.0.113.45 port 51290 ssh2"),
    ("03:17:59", "Failed password for deploy from 203.0.113.45 port 51302 ssh2"),
    ("03:18:02", "Accepted password for deploy from 203.0.113.45 port 51310 ssh2"),

    # --- 03:14 direct root login from an unrelated address
    ("03:14:22", "Accepted password for root from 192.0.2.77 port 40022 ssh2"),

    # --- 03:20 username enumeration from one address
    ("03:20:03", "Invalid user test from 198.51.100.23 port 40110"),
    ("03:20:04", "Invalid user oracle from 198.51.100.23 port 40112"),
    ("03:20:05", "Invalid user postgres from 198.51.100.23 port 40116"),
    ("03:20:07", "Invalid user ubuntu from 198.51.100.23 port 40118"),
    ("03:20:09", "Invalid user git from 198.51.100.23 port 40122"),
    ("03:20:11", "Invalid user jenkins from 198.51.100.23 port 40124"),
    ("03:20:14", "Invalid user www-data from 198.51.100.23 port 40130"),
    ("03:20:17", "Invalid user ftpuser from 198.51.100.23 port 40134"),
    ("03:20:19", "Invalid user nagios from 198.51.100.23 port 40140"),
    ("03:20:22", "Invalid user backup from 198.51.100.23 port 40144"),
    ("03:20:25", "Invalid user svn from 198.51.100.23 port 40150"),
    ("03:20:28", "Failed password for invalid user svn from 198.51.100.23 port 40152 ssh2"),

    # --- 03:30 distributed spray against 'admin' from five addresses
    ("03:30:01", "Failed password for invalid user admin from 192.0.2.101 port 41001 ssh2"),
    ("03:30:12", "Failed password for invalid user admin from 192.0.2.102 port 41012 ssh2"),
    ("03:30:24", "Failed password for invalid user admin from 192.0.2.103 port 41024 ssh2"),
    ("03:30:37", "Failed password for invalid user admin from 192.0.2.104 port 41037 ssh2"),
    ("03:30:49", "Failed password for invalid user admin from 192.0.2.105 port 41049 ssh2"),
]

SUDO = [
    ("10:43:55", "alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"),
    ("14:05:12", "bob : TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"),
    ("14:31:40", "alice : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"),
]


def auth_log_lines() -> list[str]:
    rows: list[tuple[str, str]] = []
    pid = 2400
    for time_str, message in SSHD:
        pid += 3
        rows.append((time_str, f"{DAY} {time_str} {HOST} sshd[{pid}]: {message}"))
    pid = 2650
    for time_str, message in SUDO:
        pid += 5
        rows.append((time_str, f"{DAY} {time_str} {HOST} sudo: {message}"))
    rows.sort(key=lambda row: row[0])
    return [line for _time, line in rows]


def windows_rows() -> list[str]:
    header = "TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType,Status"
    rows = [header]
    # six failed logons for 'administrator' from one address, then a success
    failures = [
        ("2026-11-20T03:21:05Z", "0xC000006D"),
        ("2026-11-20T03:21:22Z", "0xC000006D"),
        ("2026-11-20T03:21:39Z", "0xC000006A"),
        ("2026-11-20T03:21:58Z", "0xC000006A"),
        ("2026-11-20T03:22:31Z", "0xC000006D"),
        ("2026-11-20T03:22:54Z", "0xC000006D"),
    ]
    for stamp, status in failures:
        rows.append(f"{stamp},4625,WIN-DC01,administrator,203.0.113.99,3,{status}")
    rows.append("2026-11-20T03:23:41Z,4624,WIN-DC01,administrator,203.0.113.99,3,0x0")
    # normal daytime activity
    rows.append("2026-11-20T09:14:02Z,4624,WIN-DC01,alice,10.0.4.55,3,0x0")
    rows.append("2026-11-20T11:02:47Z,4625,WIN-DC01,alice,10.0.4.55,3,0xC000006A")
    rows.append("2026-11-20T11:02:58Z,4624,WIN-DC01,alice,10.0.4.55,3,0x0")
    return rows


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))

    auth_path = os.path.join(here, "auth.log")
    with open(auth_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(auth_log_lines()) + "\n")

    win_path = os.path.join(here, "windows-security.csv")
    with open(win_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(windows_rows()) + "\n")

    print(f"wrote {auth_path} ({len(auth_log_lines())} lines)")
    print(f"wrote {win_path} ({len(windows_rows()) - 1} events)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
