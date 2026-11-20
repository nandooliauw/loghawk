"""Data model for loghawk: normalised events and detections."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Event:
    """One normalised authentication event.

    ``action`` is one of ``failed``, ``accepted``, ``invalid_user``, ``sudo``,
    ``session``. ``ip`` and ``user`` are empty strings when the source log does
    not carry them.
    """

    ts: datetime
    action: str
    user: str = ""
    ip: str = ""
    host: str = ""
    detail: str = ""
    raw: str = ""
    line_no: int = 0
    source: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts.isoformat(sep=" "),
            "action": self.action,
            "user": self.user,
            "ip": self.ip,
            "host": self.host,
            "detail": self.detail,
            "line": self.line_no,
            "source": self.source,
        }


@dataclass
class Finding:
    """A detection raised by a rule."""

    id: str
    rule: str
    title: str
    severity: str
    summary: str
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    count: int = 0

    def first_seen(self) -> datetime | None:
        return min((e.ts for e in self.events), default=None)

    def last_seen(self) -> datetime | None:
        return max((e.ts for e in self.events), default=None)

    def actors(self) -> list[str]:
        seen: list[str] = []
        for event in self.events:
            label = event.ip or event.user or event.host
            if label and label not in seen:
                seen.append(label)
        return seen

    def as_dict(self) -> dict[str, Any]:
        first, last = self.first_seen(), self.last_seen()
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "count": self.count or len(self.events),
            "first_seen": first.isoformat(sep=" ") if first else None,
            "last_seen": last.isoformat(sep=" ") if last else None,
            "actors": self.actors(),
            "remediation": self.remediation,
            "references": list(self.references),
            "evidence": [
                {
                    "ts": e.ts.isoformat(sep=" "),
                    "line": e.line_no,
                    "user": e.user,
                    "ip": e.ip,
                    "detail": e.detail,
                    "raw": e.raw,
                }
                for e in self.events
            ],
        }


@dataclass
class Report:
    source: str
    generated_at: str
    events: list[Event]
    findings: list[Finding]
    parse_errors: list[str] = field(default_factory=list)
    window: int = 300
    threshold: int = 5

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id),
        )

    @property
    def counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def action_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.action] = counts.get(event.action, 0) + 1
        return dict(sorted(counts.items()))

    def timeline(self) -> list[Event]:
        return sorted(self.events, key=lambda e: e.ts)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "loghawk",
            "version": __import__("loghawk").__version__,
            "source": self.source,
            "generated_at": self.generated_at,
            "parameters": {"window_seconds": self.window, "threshold": self.threshold},
            "summary": {
                "events": len(self.events),
                "findings": len(self.findings),
                "by_severity": self.counts,
                "by_action": self.action_counts,
                "parse_errors": len(self.parse_errors),
            },
            "findings": [f.as_dict() for f in self.sorted_findings()],
            "parse_errors": self.parse_errors[:20],
        }
