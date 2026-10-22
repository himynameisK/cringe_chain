"""Проверки сборки конфигов.

Запуск из корня репозитория: python -m unittest discover -s tests -t .

Адреса в примерах — только документационные диапазоны RFC 5737 и example.com:
файл публичный, настоящих адресов и ключей в нём не бывает.
"""
from __future__ import annotations

import copy
import dataclasses
import json
import pathlib
import re
import sys
import unittest
from urllib.parse import parse_qsl, unquote, urlsplit
import base64

# Чтобы тест запускался и как `python tests/test_render.py`, а не только через discover.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cringe_chain.config import ConfigError, parse  # noqa: E402
from cringe_chain.render import chain_order, pac, share_link, singbox_config  # noqa: E402

HOP1 = {
    "name": "hop1",
    "host": "192.0.2.10",
    "port": 8388,
    "protocol": "shadowsocks",
    "method": "aes-256-gcm",
    "password": "example-password",
}
HOP2 = {
    "name": "hop2",
    "host": "198.51.100.20",
    "port": 443,
    "protocol": "vless-reality",
    "detour": "hop1",
    "uuid": "00000000-0000-4000-8000-000000000001",
    "flow": "xtls-rprx-vision",
    "server_name": "example.org",
    "public_key": "example-public-key",
    "short_id": "00ff",
}
BASE = {
    "local": {
        "singbox_config": "/tmp/cringe-chain/config.json",
        "singbox_log": "/tmp/cringe-chain/sing-box.log",
        "brew": "/opt/homebrew/bin/brew",
        "pac_dir": "/tmp/cringe-chain/pac",
        "pac_url": "http://127.0.0.1:8080/proxy.pac",
        "entry_port": 2080,
        "socks_port": 2081,
        "log_level": "info",
    },
    "routing": {
        "tunnel_domains": ["example.com", "example.org"],
        "tunnel_cidrs": ["203.0.113.0/24"],
    },
    "servers": [HOP1, HOP2],
}


def data(**over) -> dict:
    """Свежая копия примера настроек; over заменяет секции целиком."""
    out = copy.deepcopy(BASE)
    out.update(copy.deepcopy(over))
    return out


def cfg(**over):
    return parse(data(**over))


def pac_domains(text: str) -> list[str]:
    """Список доменов обратно из текста PAC."""
    found = re.search(r"var TUNNEL = (\[.*?\]);", text, re.S)
    if found is None:
        raise AssertionError("в PAC нет списка доменов — изменился формат файла")
    return json.loads(found.group(1))


def rule_with(conf: dict, key: str) -> dict | None:
    for rule in conf["route"]["rules"]:
        if key in rule:
            return rule
    return None


def outbound(conf: dict, tag: str) -> dict:
    for out in conf["outbounds"]:
        if out["tag"] == tag:
            return out
    raise AssertionError(f"в конфиге нет outbound с тегом {tag!r}")


class ChainOrderTest(unittest.TestCase):
    def test_two_links_unwind_from_first_to_last(self):
        self.assertEqual([s.name for s in chain_order(cfg())], ["hop1", "hop2"])

    def test_ring_is_rejected(self):
        # Кольцо проходит парсер: обе ссылки указывают на существующие имена.
        ring = parse(data(servers=[dict(HOP1, detour="hop2"), HOP2]))
        with self.assertRaises(ConfigError) as caught:
            chain_order(ring)
        text = str(caught.exception)
        self.assertIn("hop1", text)
        self.assertIn("hop2", text)

    def test_detour_to_nowhere_is_rejected_by_parse(self):
        with self.assertRaises(ConfigError) as caught:
            parse(data(servers=[HOP1, dict(HOP2, detour="ghost")]))
        self.assertIn("ghost", str(caught.exception))

    def test_chain_order_also_guards_detour_to_nowhere(self):
        # Config можно собрать и мимо parse, поэтому своя проверка нужна здесь тоже.
        good = cfg()
        broken = dataclasses.replace(
            good,
            servers=(good.servers[0], dataclasses.replace(good.servers[1], detour="ghost")),
        )
        with self.assertRaises(ConfigError) as caught:
            chain_order(broken)
        self.assertIn("ghost", str(caught.exception))


class SingboxConfigTest(unittest.TestCase):
    def test_second_link_goes_through_the_first(self):
        conf = singbox_config(cfg())
        self.assertNotIn("detour", outbound(conf, "hop1"))
        self.assertEqual(outbound(conf, "hop2")["detour"], "hop1")

    def test_tunnel_goes_to_the_last_link_and_the_rest_is_direct(self):
        conf = singbox_config(cfg())
        self.assertEqual(rule_with(conf, "domain_suffix")["outbound"], "hop2")
        self.assertEqual(rule_with(conf, "ip_cidr")["outbound"], "hop2")
        self.assertEqual(conf["route"]["final"], "direct")
        self.assertEqual(outbound(conf, "direct")["type"], "direct")

    def test_no_ip_rule_without_cidrs(self):
        conf = singbox_config(cfg(routing={"tunnel_domains": ["example.com"]}))
        self.assertIsNone(rule_with(conf, "ip_cidr"))

    def test_inbounds_listen_on_loopback_with_configured_ports(self):
        conf = singbox_config(cfg())
        self.assertEqual({i["listen"] for i in conf["inbounds"]}, {"127.0.0.1"})
        self.assertEqual(
            sorted(i["listen_port"] for i in conf["inbounds"]), [2080, 2081]
        )

    def test_reality_outbound_carries_params(self):
        tls = outbound(singbox_config(cfg()), "hop2")["tls"]
        self.assertEqual(tls["server_name"], "example.org")
        self.assertEqual(tls["reality"]["public_key"], "example-public-key")
        self.assertEqual(tls["reality"]["short_id"], "00ff")
        self.assertTrue(tls["utls"]["enabled"])

    def test_missing_param_names_the_server_and_the_field(self):
        no_key = {k: v for k, v in HOP2.items() if k != "public_key"}
        with self.assertRaises(ConfigError) as caught:
            singbox_config(parse(data(servers=[HOP1, no_key])))
        text = str(caught.exception)
        self.assertIn("hop2", text)
        self.assertIn("public_key", text)


class PacTest(unittest.TestCase):
    def test_domain_list_matches_singbox_exactly(self):
        # Регрессия на реальный баг: домен добавили в одно место и забыли в другом.
        for domains in (["example.com", "example.org"], ["example.com"],
                        ["example.com", "example.org", "sub.example.org"]):
            with self.subTest(domains=domains):
                conf = cfg(routing={"tunnel_domains": domains})
                self.assertEqual(
                    pac_domains(pac(conf)),
                    rule_with(singbox_config(conf), "domain_suffix")["domain_suffix"],
                )

    def test_pac_sends_listed_domains_to_the_local_ports(self):
        text = pac(cfg())
        self.assertIn("SOCKS5 127.0.0.1:2081; PROXY 127.0.0.1:2080", text)
        self.assertIn("return \"DIRECT\";", text)
        # Поддомены ловятся через dnsDomainIs с точкой, сам домен — равенством.
        self.assertIn("dnsDomainIs(host, \".\" + TUNNEL[i])", text)
        self.assertIn("host === TUNNEL[i]", text)


class ShareLinkTest(unittest.TestCase):
    def test_shadowsocks_link_parses_back(self):
        link = share_link(cfg().server("hop1"))
        parts = urlsplit(link)
        self.assertEqual(parts.scheme, "ss")
        self.assertEqual(parts.hostname, "192.0.2.10")
        self.assertEqual(parts.port, 8388)
        self.assertEqual(unquote(parts.fragment), "hop1")

        userinfo = parts.netloc.rsplit("@", 1)[0]
        self.assertNotIn("=", userinfo)  # паддинга в ss:// быть не должно
        raw = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4))
        self.assertEqual(raw.decode(), "aes-256-gcm:example-password")

    def test_reality_link_parses_back(self):
        link = share_link(cfg().server("hop2"))
        parts = urlsplit(link)
        self.assertEqual(parts.scheme, "vless")
        self.assertEqual(parts.username, HOP2["uuid"])
        self.assertEqual(parts.hostname, "198.51.100.20")
        self.assertEqual(parts.port, 443)
        self.assertEqual(unquote(parts.fragment), "hop2")

        query = dict(parse_qsl(parts.query))
        self.assertEqual(query["security"], "reality")
        self.assertEqual(query["encryption"], "none")
        self.assertEqual(query["type"], "tcp")
        self.assertEqual(query["sni"], HOP2["server_name"])
        self.assertEqual(query["pbk"], HOP2["public_key"])
        self.assertEqual(query["sid"], HOP2["short_id"])
        self.assertEqual(query["flow"], HOP2["flow"])
        self.assertEqual(query["fp"], "chrome")

    def test_missing_password_is_an_error_not_an_empty_link(self):
        no_password = {k: v for k, v in HOP1.items() if k != "password"}
        broken = parse(data(servers=[no_password, HOP2]))
        with self.assertRaises(ConfigError) as caught:
            share_link(broken.server("hop1"))
        self.assertIn("password", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
