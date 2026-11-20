"""Offline tests for loghawk. No real log files are required."""

from __future__ import annotations

import json
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loghawk.engine import run  # noqa: E402
from loghawk.models import Event, Report  # noqa: E402
from loghawk.parsers import detect_format, parse_auth_log, parse_windows_csv  # noqa: E402
from loghawk.report import to_html, to_json, to_markdown, to_text  # noqa: E402
from loghawk.rules import Config  # noqa: E402

AUTH_SAMPLE = """\
Nov 20 03:12:04 web01 sshd[2411]: Failed password for deploy from 203.0.113.45 port 51234 ssh2
Nov 20 03:12:19 web01 sshd[2414]: Failed password for deploy from 203.0.113.45 port 51240 ssh2
Nov 20 03:12:41 web01 sshd[2417]: Failed password for deploy from 203.0.113.45 port 51244 ssh2
Nov 20 03:12:52 web01 sshd[2420]: Failed password for deploy from 203.0.113.45 port 51250 ssh2
Nov 20 03:13:03 web01 sshd[2423]: Failed password for deploy from 203.0.113.45 port 51261 ssh2
Nov 20 03:13:20 web01 sshd[2426]: Accepted password for deploy from 203.0.113.45 port 51270 ssh2
Nov 20 09:05:12 web01 sshd[2440]: Accepted publickey for alice from 10.0.4.55 port 51220 ssh2
Nov 20 10:41:09 web01 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
Nov 20 03:20:03 web01 sshd[2500]: Invalid user test from 198.51.100.23 port 40110
Nov 20 03:20:04 web01 sshd[2501]: Invalid user oracle from 198.51.100.23 port 40112
Nov 20 03:20:05 web01 sshd[2502]: Invalid user ubuntu from 198.51.100.23 port 40114
Nov 20 03:20:06 web01 sshd[2503]: Invalid user git from 198.51.100.23 port 40116
"""

WINDOWS_SAMPLE = """\
TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType,Status
2026-11-20T03:21:05Z,4625,WIN-DC01,administrator,203.0.113.99,3,0xC000006D
2026-11-20T03:21:22Z,4625,WIN-DC01,administrator,203.0.113.99,3,0xC000006A
2026-11-20T03:23:41Z,4624,WIN-DC01,administrator,203.0.113.99,3,0x0
2026-11-20T09:14:02Z,4624,WIN-DC01,alice,10.0.4.55,3,0x0
"""


def events_from(text: str) -> list[Event]:
    events, _errors = parse_auth_log(text, year=2026)
    return events


def finding_by_rule(findings, rule: str):
    return [f for f in findings if f.rule == rule]


class TestParsers(unittest.TestCase):
    def test_auth_log_actions(self):
        events = events_from(AUTH_SAMPLE)
        actions = [e.action for e in events]
        self.assertEqual(actions.count("failed"), 5)
        self.assertEqual(actions.count("accepted"), 2)
        self.assertEqual(actions.count("invalid_user"), 4)
        self.assertEqual(actions.count("sudo"), 1)

    def test_auth_log_fields(self):
        first = events_from(AUTH_SAMPLE)[0]
        self.assertEqual(first.user, "deploy")
        self.assertEqual(first.ip, "203.0.113.45")
        self.assertEqual(first.host, "web01")
        self.assertEqual(first.line_no, 1)
        self.assertEqual(first.ts.year, 2026)

    def test_unparsed_line_is_reported(self):
        events, errors = parse_auth_log("this is not a syslog line\n", year=2026)
        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)

    def test_year_rollover(self):
        text = (
            "Dec 31 23:59:50 web01 sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2\n"
            "Jan  1 00:00:05 web01 sshd[2]: Failed password for a from 192.0.2.1 port 2 ssh2\n"
        )
        events, _ = parse_auth_log(text, year=2026)
        self.assertEqual(events[0].ts.year, 2026)
        self.assertEqual(events[1].ts.year, 2027)

    def test_windows_csv_mapping(self):
        events, errors = parse_windows_csv(WINDOWS_SAMPLE)
        self.assertEqual(errors, [])
        self.assertEqual([e.action for e in events], ["failed", "failed", "accepted", "accepted"])
        self.assertEqual(events[0].user, "administrator")
        self.assertIn("bad username or password", events[0].detail)

    def test_detect_format(self):
        self.assertEqual(detect_format(AUTH_SAMPLE), "authlog")
        self.assertEqual(detect_format(WINDOWS_SAMPLE), "windows_csv")
        self.assertEqual(detect_format(""), "unknown")


class TestRules(unittest.TestCase):
    def setUp(self):
        self.events = events_from(AUTH_SAMPLE)
        self.config = Config(window=300, threshold=5, lookback=3600)

    def test_brute_force_detected(self):
        findings = finding_by_rule(run(self.events, self.config), "R-01")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].count, 5)

    def test_brute_force_below_threshold_is_silent(self):
        config = Config(window=300, threshold=6, lookback=3600)
        self.assertEqual(finding_by_rule(run(self.events, config), "R-01"), [])

    def test_window_boundary_excludes_slow_attempts(self):
        # five failures span 59s, so a 30s window cannot hold five
        config = Config(window=30, threshold=5, lookback=3600)
        self.assertEqual(finding_by_rule(run(self.events, config), "R-01"), [])

    def test_success_after_failure_is_critical(self):
        findings = finding_by_rule(run(self.events, self.config), "R-02")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("deploy", findings[0].summary)

    def test_enumeration(self):
        config = Config(window=300, threshold=5, enum_distinct_users=4, lookback=3600)
        findings = finding_by_rule(run(self.events, config), "R-03")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_enumeration_needs_distinct_users(self):
        config = Config(window=300, threshold=5, enum_distinct_users=10, lookback=3600)
        self.assertEqual(finding_by_rule(run(self.events, config), "R-03"), [])

    def test_privileged_login_and_sudo(self):
        rules = {f.rule for f in run(self.events, self.config)}
        self.assertIn("R-06", rules)  # alice -> /bin/bash

    def test_spray_needs_distinct_ips(self):
        base = datetime(2026, 11, 20, 3, 30, 0)
        events = [
            Event(ts=base.replace(second=index * 5), action="failed", user="admin", ip=f"192.0.2.{index + 1}", line_no=index)
            for index in range(5)
        ]
        findings = finding_by_rule(run(events, Config(window=300, spray_distinct_ips=5)), "R-04")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")

    def test_spray_below_ip_threshold(self):
        base = datetime(2026, 11, 20, 3, 30, 0)
        events = [
            Event(ts=base.replace(second=index * 5), action="failed", user="admin", ip=f"192.0.2.{index + 1}", line_no=index)
            for index in range(3)
        ]
        self.assertEqual(finding_by_rule(run(events, Config(window=300, spray_distinct_ips=5)), "R-04"), [])

    def test_off_hours(self):
        findings = finding_by_rule(run(self.events, self.config), "R-07")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")
        self.assertTrue(all(e.ts.hour < 8 for e in findings[0].events))

    def test_windows_events_produce_findings(self):
        events, _ = parse_windows_csv(WINDOWS_SAMPLE)
        rules = {f.rule for f in run(events, Config(window=300, threshold=2, lookback=3600))}
        self.assertIn("R-01", rules)
        self.assertIn("R-05", rules)

    def test_windows_success_after_three_failures(self):
        text = (
            "TimeCreated,EventID,Computer,TargetUserName,IpAddress,LogonType,Status\n"
            "2026-11-20T03:21:05Z,4625,WIN-DC01,administrator,203.0.113.99,3,0xC000006D\n"
            "2026-11-20T03:21:22Z,4625,WIN-DC01,administrator,203.0.113.99,3,0xC000006D\n"
            "2026-11-20T03:21:39Z,4625,WIN-DC01,administrator,203.0.113.99,3,0xC000006A\n"
            "2026-11-20T03:23:41Z,4624,WIN-DC01,administrator,203.0.113.99,3,0x0\n"
        )
        events, _ = parse_windows_csv(text)
        findings = finding_by_rule(run(events, Config(window=300, threshold=3, lookback=3600)), "R-02")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")


class TestReports(unittest.TestCase):
    def build(self):
        events = events_from(AUTH_SAMPLE)
        findings = run(events, Config(window=300, threshold=5, lookback=3600))
        return Report(
            source="auth.log",
            generated_at="2026-01-01 00:00:00 UTC",
            events=events,
            findings=findings,
            parse_errors=[],
            window=300,
            threshold=5,
        )

    def test_text_mentions_severity(self):
        text = to_text(self.build(), colour=False)
        self.assertIn("CRITICAL", text)
        self.assertIn("findings", text)

    def test_markdown_has_table(self):
        text = to_markdown(self.build())
        self.assertIn("| ID | Rule |", text)

    def test_json_round_trip(self):
        data = json.loads(to_json(self.build()))
        self.assertEqual(data["tool"], "loghawk")
        self.assertEqual(data["summary"]["findings"], len(data["findings"]))
        self.assertTrue(all("evidence" in f for f in data["findings"]))

    def test_html_self_contained(self):
        markup = to_html(self.build())
        self.assertTrue(markup.startswith("<!DOCTYPE html>"))
        self.assertNotIn("http://cdn", markup)

    def test_empty_report(self):
        report = Report(source="empty", generated_at="now", events=[], findings=[])
        self.assertIn("no detections", to_text(report, colour=False).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
