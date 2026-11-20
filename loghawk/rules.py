"""Detection rules.

Every rule is a pure function ``(events, config) -> list[Finding]``. Thresholds
are explicit arguments so a report always states the parameters that produced
it, and so the tests can pin behaviour instead of depending on defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .models import Event, Finding

PRIVILEGED_USERS = {"root", "admin", "administrator"}

# sudo commands that deserve a second look even when the sudo itself succeeded.
ESCALATION_MARKERS = (
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "su -",
    "passwd",
    "/etc/shadow",
    "visudo",
    "/etc/sudoers",
    "chmod 4777",
)


@dataclass
class Config:
    window: int = 300
    threshold: int = 5
    enum_distinct_users: int = 10
    spray_distinct_ips: int = 5
    work_start: int = 8
    work_end: int = 18
    max_evidence: int = 8
    # How far back to look for failures that precede a successful login. This is
    # deliberately longer than the brute-force window: an attacker often waits
    # after hammering before using the credential they guessed.
    lookback: int = 3600


def _cap(events: list[Event], limit: int) -> list[Event]:
    """Keep the first and last few events when the list is long."""

    if len(events) <= limit:
        return events
    head = limit // 2
    tail = limit - head
    return events[:head] + events[-tail:]


def _best_window(events: list[Event], window: int, minimum: int) -> list[Event]:
    """Return the densest ``window``-second slice if it holds ``minimum`` events."""

    ordered = sorted(events, key=lambda e: e.ts)
    best: list[Event] = []
    for index, start in enumerate(ordered):
        end = start.ts + timedelta(seconds=window)
        bucket = [e for e in ordered[index:] if e.ts <= end]
        if len(bucket) > len(best):
            best = bucket
        if len(ordered) - index <= len(best):
            break
    return best if len(best) >= minimum else []


# --- R-01 brute force --------------------------------------------------------


def rule_brute_force(events: list[Event], config: Config) -> list[Finding]:
    failures: dict[str, list[Event]] = {}
    for event in events:
        if event.action == "failed" and event.ip:
            failures.setdefault(event.ip, []).append(event)

    findings = []
    for ip, attempts in sorted(failures.items()):
        bucket = _best_window(attempts, config.window, config.threshold)
        if not bucket:
            continue
        users = sorted({e.user for e in bucket if e.user})
        findings.append(
            Finding(
                id=f"R-01/{ip}",
                rule="R-01",
                title="Brute force authentication",
                severity="high",
                summary=(
                    f"{len(bucket)} failed authentications from {ip} within "
                    f"{config.window}s against {len(users)} account(s): {', '.join(users[:5])}"
                ),
                remediation=(
                    "Block the source at the firewall, and remove password-only access where "
                    "you can: keys for SSH, MFA for RDP/VPN. Add rate limiting (fail2ban, "
                    "sshd MaxAuthTries, account lockout policy) and confirm none of the "
                    "targeted accounts uses a weak password."
                ),
                references=["https://attack.mitre.org/techniques/T1110/001/"],
                events=_cap(bucket, config.max_evidence),
                count=len(bucket),
            )
        )
    return findings


# --- R-02 success after failure ---------------------------------------------


def rule_success_after_failure(events: list[Event], config: Config) -> list[Finding]:
    findings = []
    for event in events:
        if event.action != "accepted" or not event.ip:
            continue
        lookback = event.ts - timedelta(seconds=config.lookback)
        prior = [
            e
            for e in events
            if e.action == "failed"
            and e.ip == event.ip
            and lookback <= e.ts <= event.ts
        ]
        if len(prior) < max(3, config.threshold - 1):
            continue
        findings.append(
            Finding(
                id=f"R-02/{event.ip}/{event.ts:%H%M%S}",
                rule="R-02",
                title="Successful login after repeated failures",
                severity="critical",
                summary=(
                    f"{event.ip} failed {len(prior)} time(s) and then authenticated as "
                    f"'{event.user}' — treat as a probable compromise until disproven"
                ),
                remediation=(
                    "Confirm the session with the account owner, terminate it, rotate the "
                    "credential, review what the account touched after login, and check for "
                    "persistence (authorized_keys, cron, systemd units)."
                ),
                references=["https://attack.mitre.org/techniques/T1078/"],
                events=_cap(prior + [event], config.max_evidence),
                count=len(prior) + 1,
            )
        )
    return findings


# --- R-03 username enumeration ----------------------------------------------


def rule_user_enumeration(events: list[Event], config: Config) -> list[Finding]:
    by_ip: dict[str, list[Event]] = {}
    for event in events:
        if event.action in ("failed", "invalid_user") and event.ip:
            by_ip.setdefault(event.ip, []).append(event)

    findings = []
    for ip, attempts in sorted(by_ip.items()):
        ordered = sorted(attempts, key=lambda e: e.ts)
        best: list[Event] = []
        for index, start in enumerate(ordered):
            end = start.ts + timedelta(seconds=config.window)
            bucket = [e for e in ordered[index:] if e.ts <= end]
            if len({e.user for e in bucket if e.user}) > len({e.user for e in best if e.user}):
                best = bucket
        distinct = sorted({e.user for e in best if e.user})
        if len(distinct) < config.enum_distinct_users:
            continue
        findings.append(
            Finding(
                id=f"R-03/{ip}",
                rule="R-03",
                title="Username enumeration",
                severity="medium",
                summary=(
                    f"{ip} tried {len(distinct)} distinct usernames within {config.window}s "
                    f"({', '.join(distinct[:6])}{'…' if len(distinct) > 6 else ''})"
                ),
                remediation=(
                    "Block the source, and reduce the signal an attacker gets: sshd should "
                    "not reveal which accounts exist (consistent failure messages, no "
                    "Invalid user lines leaking to the client)."
                ),
                references=["https://attack.mitre.org/techniques/T1589/002/"],
                events=_cap(best, config.max_evidence),
                count=len(best),
            )
        )
    return findings


# --- R-04 password spray -----------------------------------------------------


def rule_password_spray(events: list[Event], config: Config) -> list[Finding]:
    by_user: dict[str, list[Event]] = {}
    for event in events:
        if event.action == "failed" and event.user:
            by_user.setdefault(event.user, []).append(event)

    findings = []
    for user, attempts in sorted(by_user.items()):
        ordered = sorted(attempts, key=lambda e: e.ts)
        best: list[Event] = []
        for index, start in enumerate(ordered):
            end = start.ts + timedelta(seconds=config.window)
            bucket = [e for e in ordered[index:] if e.ts <= end]
            if len({e.ip for e in bucket if e.ip}) > len({e.ip for e in best if e.ip}):
                best = bucket
        ips = sorted({e.ip for e in best if e.ip})
        if len(ips) < config.spray_distinct_ips:
            continue
        findings.append(
            Finding(
                id=f"R-04/{user}",
                rule="R-04",
                title="Distributed password spray",
                severity="high",
                summary=(
                    f"'{user}' was attacked from {len(ips)} different addresses within "
                    f"{config.window}s — the pattern of a spray, which defeats per-IP lockout"
                ),
                remediation=(
                    "Lock or rename the targeted account if it exists, enforce MFA, and add "
                    "per-account rate limiting rather than per-IP only."
                ),
                references=["https://attack.mitre.org/techniques/T1110/003/"],
                events=_cap(best, config.max_evidence),
                count=len(best),
            )
        )
    return findings


# --- R-05 privileged login ---------------------------------------------------


def rule_privileged_login(events: list[Event], config: Config) -> list[Finding]:
    privileged = [
        e for e in events if e.action == "accepted" and e.user.lower() in PRIVILEGED_USERS
    ]
    if not privileged:
        return []
    by_user: dict[str, list[Event]] = {}
    for event in privileged:
        by_user.setdefault(event.user, []).append(event)

    findings = []
    for user, items in sorted(by_user.items()):
        ips = sorted({e.ip for e in items if e.ip})
        findings.append(
            Finding(
                id=f"R-05/{user}",
                rule="R-05",
                title="Direct privileged account login",
                severity="high",
                summary=(
                    f"{len(items)} successful login(s) as '{user}' from "
                    f"{', '.join(ips) or 'unknown source'}"
                ),
                remediation=(
                    "Forbid direct root/Administrator login: require a named account and "
                    "escalate with sudo. Where it cannot be removed, restrict the source "
                    "address and require a key or MFA."
                ),
                references=["https://attack.mitre.org/techniques/T1078/003/"],
                events=_cap(items, config.max_evidence),
                count=len(items),
            )
        )
    return findings


# --- R-06 sudo escalation ----------------------------------------------------


def rule_sudo_escalation(events: list[Event], config: Config) -> list[Finding]:
    hits = [
        e
        for e in events
        if e.action == "sudo" and any(marker in e.detail for marker in ESCALATION_MARKERS)
    ]
    if not hits:
        return []
    return [
        Finding(
            id="R-06",
            rule="R-06",
            title="Privilege escalation via sudo",
            severity="medium",
            summary=(
                f"{len(hits)} sudo command(s) that open a root shell or touch credentials "
                f"({', '.join(sorted({e.user for e in hits if e.user}))})"
            ),
            remediation=(
                "Confirm each escalation was change-managed. Prefer specific sudo commands "
                "over a blanket /bin/bash, and log sudo to a remote collector so this is "
                "reviewable after the fact."
            ),
            references=["https://attack.mitre.org/techniques/T1548/003/"],
            events=_cap(hits, config.max_evidence),
            count=len(hits),
        )
    ]


# --- R-07 off-hours activity -------------------------------------------------


def rule_off_hours(events: list[Event], config: Config) -> list[Finding]:
    hits = [
        e
        for e in events
        if e.action == "accepted" and (e.ts.hour < config.work_start or e.ts.hour >= config.work_end)
    ]
    if not hits:
        return []
    return [
        Finding(
            id="R-07",
            rule="R-07",
            title="Login outside working hours",
            severity="low",
            summary=(
                f"{len(hits)} successful login(s) between "
                f"{config.work_end:02d}:00 and {config.work_start:02d}:00"
            ),
            remediation=(
                "Confirm with the account owner. If legitimate, record the on-call rota; if "
                "not, treat it as the first indicator of stolen credentials."
            ),
            references=["https://attack.mitre.org/techniques/T1078/"],
            events=_cap(hits, config.max_evidence),
            count=len(hits),
        )
    ]


ALL_RULES = (
    rule_brute_force,
    rule_success_after_failure,
    rule_user_enumeration,
    rule_password_spray,
    rule_privileged_login,
    rule_sudo_escalation,
    rule_off_hours,
)
