"""Log parsers: OpenSSH ``auth.log`` syslog and Windows Security CSV exports.

Both parsers return a list of :class:`~loghawk.models.Event`. Lines that cannot
be understood are reported as parse errors rather than silently dropped, so a
coverage gap is visible in the report.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta

from .models import Event

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# sshd message shapes we care about.
RE_FAILED = re.compile(r"Failed (?:password|publickey|keyboard-interactive/\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
RE_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
RE_INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
RE_DISCONNECT = re.compile(r"(?:Disconnected from|Connection closed by) (?:invalid user )?(?P<user>\S+)? ?(?P<ip>\S+) port")
RE_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$")
RE_SESSION = re.compile(r"(?:session opened for user|New session) (?P<user>\S+)")

# Windows Security event ids we map.
WINDOWS_EVENT_MAP = {
    "4624": "accepted",
    "4625": "failed",
    "4634": "session",
    "4647": "session",
    "4648": "accepted",
    "4672": "sudo",
    "4740": "session",
}

WINDOWS_FAILURE_REASONS = {
    "0xc000006d": "bad username or password",
    "0xc000006a": "valid username, bad password",
    "0xc0000234": "account locked out",
    "0xc0000072": "account disabled",
    "0xc000015b": "logon type not granted",
}


def parse_syslog_time(mon: str, day: str, time_str: str, year: int) -> datetime | None:
    month = MONTHS.get(mon.lower())
    if not month:
        return None
    try:
        hour, minute, second = (int(part) for part in time_str.split(":"))
        return datetime(year, month, int(day), hour, minute, second)
    except ValueError:
        return None


def parse_auth_log(text: str, year: int | None = None, source: str = "auth.log") -> tuple[list[Event], list[str]]:
    """Parse OpenSSH ``auth.log`` / ``secure`` lines.

    Syslog timestamps carry no year, so the year is inferred: the supplied year
    (or the current one) is used, and the year is incremented when the month
    number goes backwards (a December → January rollover).
    """

    events: list[Event] = []
    errors: list[str] = []
    base_year = year or datetime.now().year
    last_month: int | None = None
    year_offset = 0

    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        match = SYSLOG_RE.match(line)
        if not match:
            errors.append(f"line {index}: unrecognised syslog format")
            continue

        month = MONTHS.get(match.group("mon").lower())
        if month is None:
            errors.append(f"line {index}: unknown month {match.group('mon')!r}")
            continue
        if last_month is not None and month < last_month:
            year_offset += 1
        last_month = month

        ts = parse_syslog_time(match.group("mon"), match.group("day"), match.group("time"), base_year + year_offset)
        if ts is None:
            errors.append(f"line {index}: invalid timestamp")
            continue

        host = match.group("host")
        proc = match.group("proc")
        msg = match.group("msg")
        event = _classify_sshd(ts, host, proc, msg, raw, index, source)
        if event is None:
            continue
        events.append(event)

    return events, errors


def _classify_sshd(ts: datetime, host: str, proc: str, msg: str, raw: str, line_no: int, source: str) -> Event | None:
    if "sshd" in proc:
        failed = RE_FAILED.search(msg)
        if failed:
            return Event(
                ts=ts,
                action="failed",
                user=failed.group("user"),
                ip=failed.group("ip"),
                host=host,
                detail=f"Failed password for {failed.group('user')}",
                raw=raw,
                line_no=line_no,
                source=source,
            )
        accepted = RE_ACCEPTED.search(msg)
        if accepted:
            return Event(
                ts=ts,
                action="accepted",
                user=accepted.group("user"),
                ip=accepted.group("ip"),
                host=host,
                detail=f"Accepted {accepted.group('method')} for {accepted.group('user')}",
                raw=raw,
                line_no=line_no,
                source=source,
            )
        invalid = RE_INVALID.search(msg)
        if invalid:
            return Event(
                ts=ts,
                action="invalid_user",
                user=invalid.group("user") or "",
                ip=invalid.group("ip"),
                host=host,
                detail=f"Invalid user {invalid.group('user') or '(blank)'}",
                raw=raw,
                line_no=line_no,
                source=source,
            )
        session = RE_SESSION.search(msg)
        if session:
            return Event(
                ts=ts,
                action="session",
                user=session.group("user"),
                host=host,
                detail="Session opened",
                raw=raw,
                line_no=line_no,
                source=source,
            )
        return None

    if proc == "sudo":
        sudo = RE_SUDO.search(msg)
        if sudo:
            return Event(
                ts=ts,
                action="sudo",
                user=sudo.group("user"),
                host=host,
                detail=f"sudo as {sudo.group('target')}: {sudo.group('command')}",
                raw=raw,
                line_no=line_no,
                source=source,
            )
    return None


def parse_windows_csv(text: str, source: str = "windows-security.csv") -> tuple[list[Event], list[str]]:
    """Parse a Windows Security log CSV export.

    Expected columns (case-insensitive, order-independent): ``TimeCreated``,
    ``EventID``, ``TargetUserName``, ``IpAddress``, ``Computer``, optionally
    ``Status``/``SubStatus`` and ``LogonType``.
    """

    events: list[Event] = []
    errors: list[str] = []
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return events, ["empty file or missing header row"]

    lookup = {name.strip().lower(): name for name in reader.fieldnames if name}

    def cell(row: dict[str, str], *names: str) -> str:
        for name in names:
            key = lookup.get(name)
            if key and row.get(key):
                return str(row[key]).strip()
        return ""

    for index, row in enumerate(reader, start=2):
        event_id = cell(row, "eventid", "event id")
        action = WINDOWS_EVENT_MAP.get(event_id)
        if action is None:
            continue
        stamp = cell(row, "timecreated", "time created", "timestamp", "time")
        ts = parse_iso_time(stamp)
        if ts is None:
            errors.append(f"line {index}: unparseable timestamp {stamp!r}")
            continue
        user = cell(row, "targetusername", "target user name", "user") or cell(row, "subjectusername")
        ip = cell(row, "ipaddress", "ip address", "source network address")
        if ip in ("-", "::1", "127.0.0.1"):
            ip = ip if ip != "-" else ""
        host = cell(row, "computer", "computer name", "host")
        status = cell(row, "status", "substatus").lower()
        detail = WINDOWS_FAILURE_REASONS.get(status, f"Event {event_id}")
        logon_type = cell(row, "logontype", "logon type")
        if logon_type:
            detail = f"{detail} (logon type {logon_type})"
        events.append(
            Event(
                ts=ts,
                action=action,
                user=user,
                ip=ip,
                host=host,
                detail=detail,
                raw=",".join(f"{k}={v}" for k, v in row.items() if k),
                line_no=index,
                source=source,
            )
        )
    return events, errors


def parse_iso_time(value: str) -> datetime | None:
    cleaned = value.strip().replace("Z", "+00:00")
    for pattern in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            parsed = datetime.strptime(cleaned, pattern)
            return parsed.replace(tzinfo=None)
        except ValueError:
            continue
    return None


def detect_format(text: str) -> str:
    """Guess the log type from the first non-empty lines."""

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{") or line.startswith("["):
            return "json"
        if SYSLOG_RE.match(line):
            return "authlog"
        if "," in line and re.search(r"eventid|timecreated", line, re.I):
            return "windows_csv"
        if "," in line and line.count(",") >= 3:
            return "windows_csv"
        return "unknown"
    return "unknown"


def parse_any(text: str, year: int | None = None, source: str = "log") -> tuple[list[Event], list[str], str]:
    """Parse by detected format and return ``(events, errors, format)``."""

    fmt = detect_format(text)
    if fmt == "authlog":
        events, errors = parse_auth_log(text, year=year, source=source)
    elif fmt == "windows_csv":
        events, errors = parse_windows_csv(text, source=source)
    else:
        events, errors = [], [f"could not detect log format for {source}"]
    return events, errors, fmt


def within_window(events: list[Event], start: datetime, seconds: int) -> list[Event]:
    return [e for e in events if start <= e.ts <= start + timedelta(seconds=seconds)]
