"""Rule engine: run every rule over the parsed events."""

from __future__ import annotations

from .models import Event, Finding
from .rules import ALL_RULES, Config


def run(events: list[Event], config: Config | None = None) -> list[Finding]:
    """Run all rules and return findings, worst first."""

    config = config or Config()
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(events, config))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (order.get(f.severity, 9), f.id))


def coverage(events: list[Event], findings: list[Finding]) -> dict[str, int]:
    """How many parsed events are referenced by at least one finding."""

    referenced = {id(event) for finding in findings for event in finding.events}
    return {
        "events": len(events),
        "in_findings": len(referenced),
        "silent": len(events) - len(referenced),
    }
