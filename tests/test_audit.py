"""Проверки разбора журнала sing-box.

Все адреса и домены — документационные (RFC 5737, RFC 2606).
"""
from __future__ import annotations

import ipaddress
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cringe_chain.audit import (
    Connection,
    audit_file,
    covered,
    find_leaks,
    looks_ours,
    parse_log,
    tunnel_marks,
    tunnel_rules,
)
from cringe_chain.config import ConfigError

# Конфиг sing-box в том виде, в каком его читает tunnel_rules.
SINGBOX_CFG = {
    "outbounds": [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "shadowsocks", "tag": "hop"},
    ],
    "route": {
        "rules": [
            {
                "outbound": "hop",
                "domain_suffix": [".example.com"],
                "ip_cidr": ["203.0.113.0/24", "не-подсеть"],
            },
            {"outbound": "hop", "domain": ["EXACT.example.org"]},
            {
                "outbound": "direct",
                "domain_suffix": ["bypass.example.org"],
                "ip_cidr": ["192.0.2.0/24"],
            },
        ]
    },
}

EDITED = datetime(2026, 10, 22, 12, 0, 0)


def _type_of(tag: str) -> str:
    """В журнале перед тегом стоит тип outbound'а, а не само слово direct."""
    return "direct" if tag == "direct" else "shadowsocks"


def opened(ts: str, cid: str, tag: str, host: str, packet: bool = False) -> str:
    kind = "outbound packet connection" if packet else "outbound connection"
    return (f"+0300 {ts} INFO [{cid} 0ms] outbound/{_type_of(tag)}[{tag}]: "
            f"{kind} to {host}:443")


def failed(ts: str, cid: str, tag: str, host: str) -> str:
    return (f"+0300 {ts} ERROR [{cid} 10.0s] connection: open connection to "
            f"{host}:443 using outbound/{_type_of(tag)}[{tag}]: "
            f"lookup {host}: no such host")


class TestTunnelRules(unittest.TestCase):
    def test_takes_only_tunnel_outbound_rules(self):
        suffixes, cidrs = tunnel_rules(SINGBOX_CFG)
        # Правило на direct описывает обход туннеля — его брать нельзя.
        self.assertEqual(suffixes, {"example.com", "exact.example.org"})
        self.assertEqual(cidrs, [ipaddress.ip_network("203.0.113.0/24")])

    def test_broken_config_is_loud(self):
        # Молчаливый пустой набор правил дал бы «утечек нет» на любом логе.
        with self.assertRaises(ConfigError):
            tunnel_rules({"route": {"rules": []}})

    def test_field_written_as_string_not_list(self):
        # sing-box принимает эти поля и строкой; перебор по строке дал бы
        # буквы вместо доменов и сети вида 0.0.0.2/32.
        cfg = {
            "outbounds": [{"type": "shadowsocks", "tag": "hop"}],
            "route": {"rules": [{
                "outbound": "hop",
                "domain_suffix": "example.com",
                "ip_cidr": "203.0.113.0/24",
            }]},
        }
        suffixes, cidrs = tunnel_rules(cfg)
        self.assertEqual(suffixes, {"example.com"})
        self.assertEqual(cidrs, [ipaddress.ip_network("203.0.113.0/24")])

    def test_no_rules_is_empty_not_crash(self):
        cfg = {"outbounds": [{"type": "shadowsocks", "tag": "hop"}]}
        self.assertEqual(tunnel_rules(cfg), (set(), []))


class TestCovered(unittest.TestCase):
    def setUp(self):
        self.suffixes, self.cidrs = tunnel_rules(SINGBOX_CFG)

    def test_domain_suffix(self):
        self.assertTrue(covered("api.example.com", self.suffixes, self.cidrs))
        self.assertTrue(covered("example.com", self.suffixes, self.cidrs))
        self.assertFalse(covered("api.example.org", self.suffixes, self.cidrs))

    def test_not_a_substring_match(self):
        # «notexample.com» не входит в зону example.com.
        self.assertFalse(covered("notexample.com", self.suffixes, self.cidrs))

    def test_ip_host_matches_cidr(self):
        self.assertTrue(covered("203.0.113.9", self.suffixes, self.cidrs))
        self.assertFalse(covered("192.0.2.9", self.suffixes, self.cidrs))


class TestTunnelMarks(unittest.TestCase):
    def test_only_two_part_suffixes_of_four_letters(self):
        marks = tunnel_marks({"example.com", "api.service.example.com", "ab.example"})
        # Из трёхсоставного вышла бы слишком общая примета, из «ab» — слишком короткая.
        self.assertEqual(marks, {"example"})


class TestLooksOurs(unittest.TestCase):
    def test_whole_label_matches(self):
        self.assertTrue(looks_ours("claude.example.org", {"claude"}))

    def test_hyphen_part_matches(self):
        self.assertTrue(looks_ours("api-claude.example.org", {"claude"}))

    def test_substring_does_not_match(self):
        # Доля имени сравнивается целиком, иначе примета ловит пол-интернета.
        self.assertFalse(looks_ours("claudecompanyunrelated.example.com", {"claude"}))
        self.assertFalse(looks_ours("unclaude.example.org", {"claude"}))

    def test_no_marks_no_suspects(self):
        self.assertFalse(looks_ours("api.example.com", set()))


class TestParseLog(unittest.TestCase):
    def test_info_and_error_with_same_id_are_one_connection(self):
        lines = [
            opened("2026-10-22 12:50:55", "1292947266", "direct", "api.example.com"),
            failed("2026-10-22 12:50:55", "1292947266", "direct", "api.example.com"),
        ]
        conns = parse_log(lines)
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].host, "api.example.com")
        self.assertEqual(conns[0].cid, "1292947266")
        self.assertEqual(conns[0].tag, "direct")

    def test_same_host_different_ids_are_two_connections(self):
        lines = [
            opened("2026-10-22 12:50:55", "1", "direct", "api.example.com"),
            opened("2026-10-22 12:50:56", "2", "direct", "api.example.com"),
        ]
        self.assertEqual(len(parse_log(lines)), 2)

    def test_packet_connection_and_tunnel_tag(self):
        line = opened("2026-10-22 12:51:00", "3", "hop", "exact.example.org", packet=True)
        conns = parse_log([line])
        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].tag, "hop")

    def test_host_is_lowercased(self):
        conns = parse_log([opened("2026-10-22 12:51:00", "4", "direct", "API.Example.COM")])
        self.assertEqual(conns[0].host, "api.example.com")

    def test_broken_lines_are_skipped(self):
        lines = [
            "",
            "   ",
            "мусор без отметки времени",
            "+0300 2026-10-22 12:51:01 INFO [abc 0ms] outbound/direct[direct]: "
            "outbound connection to api.example.com:443",       # номер не число
            "+0300 2026-10-22 12:51:02 INFO [5 0ms] outbound/direct[direct]: "
            "outbound connection to api.example.com",           # нет порта
            "+0300 2026-10-22 12:51:03 INFO [6 0ms] router: sniffed protocol tls",
            opened("2026-10-22 12:51:04", "7", "direct", "api.example.com"),
        ]
        conns = parse_log(lines)
        self.assertEqual([c.cid for c in conns], ["7"])


class TestFindLeaks(unittest.TestCase):
    def setUp(self):
        self.suffixes, self.cidrs = tunnel_rules(SINGBOX_CFG)
        self.marks = {"widget"}
        self.conns = [
            # покрыт правилом, ушёл прямо ПОСЛЕ правки конфига
            Connection("2026-10-22 12:50:55", "1", "direct", "api.example.com"),
            Connection("2026-10-22 12:52:00", "2", "direct", "api.example.com"),
            # покрыт правилом, но ушёл прямо ДО правки
            Connection("2026-10-22 11:00:00", "3", "direct", "old.example.com"),
            # похож на наш по примете, правила нет
            Connection("2026-10-22 12:50:00", "4", "direct", "widget.example.org"),
            # ни то ни другое — к отчёту отношения не имеет
            Connection("2026-10-22 12:50:10", "5", "direct", "plain.example.org"),
            # ушёл в туннель, как и должен
            Connection("2026-10-22 12:53:00", "6", "hop", "exact.example.org"),
        ]

    def report(self, mtime=EDITED):
        return find_leaks(self.conns, self.suffixes, self.cidrs, self.marks, mtime)

    def test_covered_after_edit_is_stale(self):
        rep = self.report()
        self.assertEqual([leak.host for leak in rep.stale], ["api.example.com"])
        stale = rep.stale[0]
        self.assertEqual(stale.count, 2)
        self.assertEqual(stale.first, "2026-10-22 12:50:55")
        self.assertEqual(stale.last, "2026-10-22 12:52:00")

    def test_covered_before_edit_is_explained_not_stale(self):
        rep = self.report()
        self.assertEqual([leak.host for leak in rep.explained], ["old.example.com"])
        self.assertNotIn("old.example.com", [leak.host for leak in rep.stale])

    def test_looks_ours_without_rule_is_missing(self):
        rep = self.report()
        self.assertEqual([leak.host for leak in rep.missing], ["widget.example.org"])

    def test_unrelated_host_is_not_reported(self):
        rep = self.report()
        reported = {leak.host for leak in rep.stale + rep.missing + rep.explained}
        self.assertNotIn("plain.example.org", reported)

    def test_counters_cover_every_connection(self):
        rep = self.report()
        self.assertEqual(rep.total, 6)
        self.assertEqual(rep.direct, 5)
        self.assertEqual(rep.first_ts, "2026-10-22 11:00:00")
        self.assertEqual(rep.last_ts, "2026-10-22 12:53:00")
        self.assertFalse(rep.ok)

    def test_without_mtime_everything_covered_is_stale(self):
        rep = self.report(mtime=None)
        self.assertEqual(
            sorted(leak.host for leak in rep.stale),
            ["api.example.com", "old.example.com"],
        )
        self.assertEqual(rep.explained, [])

    def test_aware_mtime_does_not_break_comparison(self):
        # datetime с зоной не должен ронять сравнение с отметками журнала.
        rep = self.report(mtime=EDITED.replace(tzinfo=timezone(timedelta(hours=3))))
        self.assertTrue(rep.stale or rep.explained)

    def test_clean_log_is_ok(self):
        rep = find_leaks(
            [Connection("2026-10-22 12:53:00", "1", "hop", "api.example.com")],
            self.suffixes, self.cidrs, self.marks, EDITED,
        )
        self.assertTrue(rep.ok)
        self.assertEqual(rep.direct, 0)


class TestAuditFile(unittest.TestCase):
    def test_reads_log_and_reports(self):
        lines = [
            opened("2026-10-22 12:50:55", "1", "direct", "api.example.com"),
            failed("2026-10-22 12:50:55", "1", "direct", "api.example.com"),
            opened("2026-10-22 12:50:56", "2", "direct", "widget.example.org"),
            "битая строка",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "sing-box.log"
            # \udcff — байт, который не разбирается как utf-8: errors="replace".
            log.write_bytes("\n".join(lines).encode() + b"\n\xff\n")
            rep = audit_file(SINGBOX_CFG, log, EDITED)
        self.assertEqual(rep.total, 2)
        self.assertEqual(rep.direct, 2)
        self.assertEqual([leak.host for leak in rep.stale], ["api.example.com"])
        # Примета «example» выведена из example.com, поэтому хост из example.org
        # без правила попадает в утечки.
        self.assertEqual([leak.host for leak in rep.missing], ["widget.example.org"])


if __name__ == "__main__":
    unittest.main()
