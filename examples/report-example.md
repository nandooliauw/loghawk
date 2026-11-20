# loghawk report

- **Source:** `auth.log` (authlog)
- **Generated:** 2026-11-20 03:19:27 UTC
- **Events parsed:** 35
- **Parameters:** window 300s, threshold 5
- **Parse errors:** 0

## Findings

`1 critical` · `3 high` · `2 medium` · `1 low`

| ID | Rule | Finding | Severity | Events | Window |
| --- | --- | --- | --- | --- | --- |
| `R-02/203.0.113.45/031802` | R-02 | Successful login after repeated failures | **CRITICAL** | 9 | 03:12:04 → 03:18:02 |
| `R-01/203.0.113.45` | R-01 | Brute force authentication | **HIGH** | 7 | 03:12:04 → 03:16:11 |
| `R-04/admin` | R-04 | Distributed password spray | **HIGH** | 5 | 03:30:01 → 03:30:49 |
| `R-05/root` | R-05 | Direct privileged account login | **HIGH** | 1 | 03:14:22 |
| `R-03/198.51.100.23` | R-03 | Username enumeration | **MEDIUM** | 12 | 03:20:03 → 03:20:28 |
| `R-06` | R-06 | Privilege escalation via sudo | **MEDIUM** | 1 | 14:05:12 |
| `R-07` | R-07 | Login outside working hours | **LOW** | 2 | 03:14:22 → 03:18:02 |

### 1. R-02/203.0.113.45/031802 — Successful login after repeated failures

- **Severity:** CRITICAL
- **Summary:** 203.0.113.45 failed 8 time(s) and then authenticated as 'deploy' — treat as a probable compromise until disproven
- **Events:** 9
- **Remediation:** Confirm the session with the account owner, terminate it, rotate the credential, review what the account touched after login, and check for persistence (authorized_keys, cron, systemd units).
- **Reference:** https://attack.mitre.org/techniques/T1078/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 1 | 03:12:04 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 2 | 03:12:19 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 3 | 03:12:41 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 4 | 03:13:07 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 7 | 03:14:38 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 8 | 03:16:11 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 9 | 03:17:59 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 10 | 03:18:02 | accepted | deploy | 203.0.113.45 | Accepted password for deploy |
| … | | | | | 1 more event(s) not shown (evidence capped) |

### 2. R-01/203.0.113.45 — Brute force authentication

- **Severity:** HIGH
- **Summary:** 7 failed authentications from 203.0.113.45 within 300s against 1 account(s): deploy
- **Events:** 7
- **Remediation:** Block the source at the firewall, and remove password-only access where you can: keys for SSH, MFA for RDP/VPN. Add rate limiting (fail2ban, sshd MaxAuthTries, account lockout policy) and confirm none of the targeted accounts uses a weak password.
- **Reference:** https://attack.mitre.org/techniques/T1110/001/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 1 | 03:12:04 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 2 | 03:12:19 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 3 | 03:12:41 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 4 | 03:13:07 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 5 | 03:13:52 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 7 | 03:14:38 | failed | deploy | 203.0.113.45 | Failed password for deploy |
| 8 | 03:16:11 | failed | deploy | 203.0.113.45 | Failed password for deploy |

### 3. R-04/admin — Distributed password spray

- **Severity:** HIGH
- **Summary:** 'admin' was attacked from 5 different addresses within 300s — the pattern of a spray, which defeats per-IP lockout
- **Events:** 5
- **Remediation:** Lock or rename the targeted account if it exists, enforce MFA, and add per-account rate limiting rather than per-IP only.
- **Reference:** https://attack.mitre.org/techniques/T1110/003/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 23 | 03:30:01 | failed | admin | 192.0.2.101 | Failed password for admin |
| 24 | 03:30:12 | failed | admin | 192.0.2.102 | Failed password for admin |
| 25 | 03:30:24 | failed | admin | 192.0.2.103 | Failed password for admin |
| 26 | 03:30:37 | failed | admin | 192.0.2.104 | Failed password for admin |
| 27 | 03:30:49 | failed | admin | 192.0.2.105 | Failed password for admin |

### 4. R-05/root — Direct privileged account login

- **Severity:** HIGH
- **Summary:** 1 successful login(s) as 'root' from 192.0.2.77
- **Events:** 1
- **Remediation:** Forbid direct root/Administrator login: require a named account and escalate with sudo. Where it cannot be removed, restrict the source address and require a key or MFA.
- **Reference:** https://attack.mitre.org/techniques/T1078/003/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 6 | 03:14:22 | accepted | root | 192.0.2.77 | Accepted password for root |

### 5. R-03/198.51.100.23 — Username enumeration

- **Severity:** MEDIUM
- **Summary:** 198.51.100.23 tried 11 distinct usernames within 300s (backup, ftpuser, git, jenkins, nagios, oracle…)
- **Events:** 12
- **Remediation:** Block the source, and reduce the signal an attacker gets: sshd should not reveal which accounts exist (consistent failure messages, no Invalid user lines leaking to the client).
- **Reference:** https://attack.mitre.org/techniques/T1589/002/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 11 | 03:20:03 | invalid_user | test | 198.51.100.23 | Invalid user test |
| 12 | 03:20:04 | invalid_user | oracle | 198.51.100.23 | Invalid user oracle |
| 13 | 03:20:05 | invalid_user | postgres | 198.51.100.23 | Invalid user postgres |
| 14 | 03:20:07 | invalid_user | ubuntu | 198.51.100.23 | Invalid user ubuntu |
| 19 | 03:20:19 | invalid_user | nagios | 198.51.100.23 | Invalid user nagios |
| 20 | 03:20:22 | invalid_user | backup | 198.51.100.23 | Invalid user backup |
| 21 | 03:20:25 | invalid_user | svn | 198.51.100.23 | Invalid user svn |
| 22 | 03:20:28 | failed | svn | 198.51.100.23 | Failed password for svn |
| … | | | | | 4 more event(s) not shown (evidence capped) |

### 6. R-06 — Privilege escalation via sudo

- **Severity:** MEDIUM
- **Summary:** 1 sudo command(s) that open a root shell or touch credentials (bob)
- **Events:** 1
- **Remediation:** Confirm each escalation was change-managed. Prefer specific sudo commands over a blanket /bin/bash, and log sudo to a remote collector so this is reviewable after the fact.
- **Reference:** https://attack.mitre.org/techniques/T1548/003/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 33 | 14:05:12 | sudo | bob | - | sudo as root: /bin/bash |

### 7. R-07 — Login outside working hours

- **Severity:** LOW
- **Summary:** 2 successful login(s) between 18:00 and 08:00
- **Events:** 2
- **Remediation:** Confirm with the account owner. If legitimate, record the on-call rota; if not, treat it as the first indicator of stolen credentials.
- **Reference:** https://attack.mitre.org/techniques/T1078/

| Line | Time | Action | User | Source | Detail |
| --- | --- | --- | --- | --- | --- |
| 6 | 03:14:22 | accepted | root | 192.0.2.77 | Accepted password for root |
| 10 | 03:18:02 | accepted | deploy | 203.0.113.45 | Accepted password for deploy |
