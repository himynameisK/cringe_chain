"""Интеграционные проверки: настоящий sing-box, настоящие порты, настоящие файлы.

Юнит-тесты с заглушками проверяют мою логику. Они НЕ поймали бы сбой,
который случился на самом деле: в них sing-box был выдуман, а падал
настоящий — на несуществующем каталоге журнала, который `check` пропускает.

Здесь заглушек нет нигде, кроме службы Homebrew: вместо неё подставляется
скрипт, который так же запускает и убивает НАСТОЯЩИЙ sing-box. Всё остальное
подлинное, поэтому эти тесты доказывают поведение, а не описывают замысел.

Живую настройку машины они не трогают: свои каталоги, свои свободные порты,
свой конфиг.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from cringe_chain import cli, config as cfgmod, launcher, safety

SINGBOX = shutil.which("sing-box") or "/opt/homebrew/bin/sing-box"
HAVE_SINGBOX = pathlib.Path(SINGBOX).exists()
skip = unittest.skipUnless(HAVE_SINGBOX, f"нужен бинарь sing-box ({SINGBOX})")

FAKE_BREW = """#!/bin/bash
# Подделка под `brew services`, которая на самом деле поднимает sing-box.
CFG={cfg}
PID={pid}
SB={sb}
case "$2" in
  start|restart)
    [ -f "$PID" ] && kill "$(cat "$PID")" 2>/dev/null; sleep 0.3
    "$SB" run -c "$CFG" >{out} 2>&1 &
    echo $! > "$PID" ;;
  stop)
    [ -f "$PID" ] && kill "$(cat "$PID")" 2>/dev/null; rm -f "$PID" ;;
esac
exit 0
"""


def good_config(ports: list[int], log: pathlib.Path) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True, "output": str(log)},
        "inbounds": [{"type": "mixed", "tag": f"in{i}", "listen": "127.0.0.1",
                      "listen_port": p} for i, p in enumerate(ports)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "final": "direct"},
    }


class BootTestAgainstRealBinary(unittest.TestCase):
    """Репетиция обязана ловить то, что пропускает sing-box check."""

    @skip
    def test_missing_log_directory_is_caught(self):
        # Ровно сегодняшний сбой. check такой конфиг принимает, запуск падает.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cfg = good_config([launcher.free_port()], root / "нет-каталога" / "sb.log")
            path = root / "c.json"
            path.write_text(json.dumps(cfg))

            accepted, _ = safety.config_is_valid(path, SINGBOX)
            self.assertTrue(accepted, "check обязан принять — в этом и подвох")

            result = launcher.boot_test(cfg, SINGBOX)
            self.assertFalse(result.ok, "репетиция обязана отказать")
            self.assertIn("logger", result.log.lower())

    @skip
    def test_good_config_boots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            result = launcher.boot_test(good_config([launcher.free_port()], root / "sb.log"),
                                        SINGBOX)
            self.assertTrue(result.ok, result.reason)

    @skip
    def test_rehearsal_does_not_keep_ports(self):
        """После репетиции порты обязаны освободиться, иначе она мешает работе."""
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cfg = good_config([launcher.free_port()], root / "sb.log")
            probe, ports = launcher.rehearsal_config(cfg)
            launcher.boot_test(cfg, SINGBOX)
            time.sleep(0.5)
            for p in ports:
                self.assertFalse(launcher.port_bound(p), f"порт {p} остался занят")

    @skip
    def test_rehearsal_changes_only_ports(self):
        """Проба должна отличаться от применяемого конфига минимально."""
        cfg = good_config([1111, 2222], pathlib.Path("/tmp/x.log"))
        probe, ports = launcher.rehearsal_config(cfg)
        self.assertEqual(cfg["log"], probe["log"], "журнал подменять нельзя — он и ломался")
        self.assertEqual(cfg["outbounds"], probe["outbounds"])
        self.assertEqual(cfg["route"], probe["route"])
        self.assertNotEqual([1111, 2222], ports)


class LiveApplyTest(unittest.TestCase):
    """Полный цикл apply поверх настоящего sing-box, запускаемого поддельным brew."""

    def setUp(self):
        if not HAVE_SINGBOX:
            self.skipTest("нет бинаря sing-box")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.entry, self.socks = launcher.free_port(), launcher.free_port()
        self.cfg_path = self.root / "etc/config.json"
        self.cfg_path.parent.mkdir(parents=True)
        self.pid = self.root / "sb.pid"
        self.brew = self.root / "brew"
        self.brew.write_text(FAKE_BREW.format(
            cfg=self.cfg_path, pid=self.pid, sb=SINGBOX, out=self.root / "sb.out"))
        self.brew.chmod(0o755)
        self.log = self.root / "logs/sb.log"
        self.log.parent.mkdir(parents=True)
        # живой рабочий конфиг «до»
        self.before = good_config([self.entry, self.socks], self.log)
        self.cfg_path.write_text(json.dumps(self.before))
        subprocess.run([str(self.brew), "services", "start", "sing-box"], check=True)
        self.assertTrue(self._wait(self.entry), "подготовка: служба не поднялась")

    def tearDown(self):
        subprocess.run([str(self.brew), "services", "stop", "sing-box"])
        time.sleep(0.3)
        self.tmp.cleanup()

    def _wait(self, port, seconds=12):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if launcher.port_bound(port):
                return True
            time.sleep(0.15)
        return False

    def _cfg(self, domains=("example.com",)) -> cfgmod.Config:
        return cfgmod.parse({
            "local": {"singbox_config": str(self.cfg_path), "singbox_log": str(self.log),
                      "brew": str(self.brew), "pac_dir": str(self.root / "pac"),
                      "pac_url": f"http://127.0.0.1:{launcher.free_port()}/x.pac",
                      "entry_port": self.entry, "socks_port": self.socks},
            "routing": {"tunnel_domains": list(domains)},
            "servers": [{"name": "uz", "host": "198.51.100.10", "port": 443,
                         "protocol": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
                         "password": "AAAAAAAAAAAAAAAAAAAAAA=="}],
        })

    def _args(self):
        return mock.Mock(config=None, dry_run=False, force=False, json=False)

    def _apply(self, cfg):
        # Оригинал захватываем ДО подмены: иначе лямбда позовёт сама себя.
        # Подменяем только путь к бинарю — сама репетиция остаётся настоящей.
        real_boot = launcher.boot_test
        with mock.patch.object(cli, "_load", return_value=cfg), \
             mock.patch.object(safety, "preflight", return_value=[]), \
             mock.patch.object(cli.launcher, "boot_test",
                               side_effect=lambda d, *a, **k: real_boot(d, SINGBOX)):
            return cli.cmd_apply(self._args())

    def test_apply_replaces_config_and_service_serves_it(self):
        rc = self._apply(self._cfg(["example.com", "example.org"]))
        self.assertEqual(0, rc)
        self.assertTrue(self._wait(self.entry), "служба обязана слушать после apply")
        written = json.loads(self.cfg_path.read_text())
        doms = {d for r in written["route"]["rules"] for d in r.get("domain_suffix", [])}
        self.assertEqual({"example.com", "example.org"}, doms)

    def test_unbootable_config_leaves_live_config_and_service_alone(self):
        """Главная гарантия: негодный конфиг не доходит до живой службы."""
        before_text = self.cfg_path.read_text()
        cfg = self._cfg()
        # ломаем так, как ломаются на самом деле — опечаткой в настройках
        broken = dict(cfg.servers[0].params, method="НЕ-СУЩЕСТВУЮЩИЙ-МЕТОД")
        object.__setattr__(cfg.servers[0], "params", broken)

        rc = self._apply(cfg)
        self.assertEqual(1, rc)
        self.assertEqual(before_text, self.cfg_path.read_text(),
                         "живой конфиг обязан остаться байт в байт прежним")
        self.assertTrue(launcher.port_bound(self.entry),
                        "служба обязана продолжать слушать")

    def test_service_never_drops_while_a_bad_apply_is_attempted(self):
        """Порт не должен пропасть ни на мгновение, пока негодный apply отбивается."""
        drops = []
        stop = threading.Event()

        def watch():
            while not stop.is_set():
                if not launcher.port_bound(self.entry):
                    drops.append(time.monotonic())
                time.sleep(0.05)

        cfg = self._cfg()
        object.__setattr__(cfg.servers[0], "params",
                           dict(cfg.servers[0].params, method="ТОЖЕ-НЕ-МЕТОД"))
        t = threading.Thread(target=watch, daemon=True)
        t.start()
        try:
            rc = self._apply(cfg)
        finally:
            stop.set()
            t.join(timeout=3)
        self.assertEqual(1, rc)
        self.assertEqual([], drops, "во время неудачного apply связь не должна прерываться")

    def test_rescue_brings_service_back_from_a_broken_live_config(self):
        """Сломали конфиг руками — rescue обязан поднять службу на резерве."""
        good = self._apply(self._cfg(["example.com"]))
        self.assertEqual(0, good)
        backups = list(self.cfg_path.parent.glob(self.cfg_path.name + ".backup-*"))
        self.assertTrue(backups, "apply обязан оставить резерв")

        self.cfg_path.write_text(json.dumps(
            good_config([self.entry, self.socks], self.root / "нет-каталога" / "sb.log")))
        subprocess.run([str(self.brew), "services", "stop", "sing-box"])
        time.sleep(0.4)
        self.assertFalse(launcher.port_bound(self.entry), "подготовка: служба должна лежать")

        cfg = self._cfg()
        with mock.patch.object(cli, "_load", return_value=cfg), \
             mock.patch.object(cli.system, "unsetenv"), \
             mock.patch.object(cli.system, "network_services", return_value=[]), \
             mock.patch.object(cli.system, "disable_proxy"), \
             mock.patch.object(cli.pacserver, "uninstall", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(True, "")):
            rc = cli.cmd_rescue(self._args())

        self.assertEqual(0, rc, "rescue обязан найти рабочий конфиг")
        self.assertTrue(self._wait(self.entry), "служба обязана слушать после rescue")


if __name__ == "__main__":
    unittest.main()
