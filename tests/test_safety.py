"""Проверки предохранителей и отката.

Главный тест здесь — test_failed_start_restores_previous_config: он
воспроизводит ровно тот сбой, из-за которого всё и писалось, и требует,
чтобы прежний конфиг вернулся на диск сам.
"""
from __future__ import annotations

import json
import pathlib
import plistlib
import tempfile
import unittest
from unittest import mock

from cringe_chain import cli, config as cfgmod, safety


def make_cfg(root: pathlib.Path, entry=43210, socks=43211) -> cfgmod.Config:
    return cfgmod.parse({
        "local": {
            "singbox_config": str(root / "etc/config.json"),
            "singbox_log": str(root / "logs/deep/sing-box.log"),
            "brew": str(root / "bin/brew"),
            "pac_dir": str(root / "pac"),
            "pac_url": f"http://127.0.0.1:{entry + 100}/x.pac",
            "entry_port": entry,
            "socks_port": socks,
        },
        "routing": {"tunnel_domains": ["example.com"], "no_proxy": [".internal.example.org"]},
        "servers": [{"name": "uz", "host": "198.51.100.10", "port": 443,
                     "protocol": "shadowsocks", "method": "2022-blake3-aes-128-gcm",
                     "password": "cGFzc3dvcmQtZm9yLXRlc3Rz"}],
    })


class EnsureDirsTest(unittest.TestCase):
    def test_log_directory_is_created(self):
        # Пропущенный каталог журнала — причина двухчасового простоя:
        # sing-box не создаёт его сам и просто не стартует.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cfg = make_cfg(root)
            self.assertFalse(cfg.local.singbox_log.parent.exists())
            safety.ensure_dirs(cfg, root / "pac/x.pac")
            self.assertTrue(cfg.local.singbox_log.parent.exists())
            self.assertTrue(cfg.local.singbox_config.parent.exists())
            self.assertTrue((root / "pac").exists())


class ConfigSwapTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "config.json"
        self.path.write_text('{"прежний": true}')

    def tearDown(self):
        self.tmp.cleanup()

    def test_without_commit_previous_file_returns(self):
        with safety.ConfigSwap(self.path, '{"новый": true}') as swap:
            self.assertIn("новый", self.path.read_text())
            self.assertTrue(swap.backup.exists())
        self.assertIn("прежний", self.path.read_text())

    def test_commit_keeps_new_file(self):
        with safety.ConfigSwap(self.path, '{"новый": true}') as swap:
            swap.commit()
        self.assertIn("новый", self.path.read_text())

    def test_exception_inside_also_restores(self):
        with self.assertRaises(RuntimeError):
            with safety.ConfigSwap(self.path, '{"новый": true}'):
                raise RuntimeError("что-то пошло не так")
        self.assertIn("прежний", self.path.read_text())

    def test_backups_are_pruned(self):
        for i in range(14):
            with safety.ConfigSwap(self.path, '{"n": %d}' % i, keep=5) as swap:
                swap.commit()
        self.assertLessEqual(len(list(self.path.parent.glob("config.json.backup-*"))), 5)

    def test_no_previous_file_means_nothing_to_restore(self):
        fresh = pathlib.Path(self.tmp.name) / "fresh.json"
        with safety.ConfigSwap(fresh, "{}") as swap:
            self.assertIsNone(swap.backup)
            self.assertFalse(swap.restore())


class RunningConfigPathTest(unittest.TestCase):
    def test_parses_long_and_short_flag(self):
        for line, want in (
            ("/opt/homebrew/opt/sing-box/bin/sing-box run --config /etc/sb.json --directory /x",
             "/etc/sb.json"),
            ("/usr/local/bin/sing-box -c /other/path.json", "/other/path.json"),
        ):
            with mock.patch("subprocess.run") as run:
                run.return_value = mock.Mock(stdout=line)
                self.assertEqual(str(safety.running_config_path()), want)

    def test_no_process_means_unknown(self):
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.Mock(stdout="/usr/sbin/cupsd -l\n")
            self.assertIsNone(safety.running_config_path())


class ForeignAgentsTest(unittest.TestCase):
    def test_finds_other_pac_server_and_skips_our_own(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = pathlib.Path(tmp)
            agents = home / "Library/LaunchAgents"
            agents.mkdir(parents=True)
            served = home / "served"
            served.mkdir()
            (served / "proxy.pac").write_text("function FindProxyForURL(){}")
            for label in ("local.pac-server", "com.cringe-chain.pac"):
                with open(agents / f"{label}.plist", "wb") as fh:
                    plistlib.dump({"Label": label, "ProgramArguments":
                                   ["/usr/bin/python3", "-m", "http.server", "8899",
                                    "--directory", str(served)]}, fh)
            with mock.patch("pathlib.Path.home", return_value=home):
                found = safety.foreign_pac_agents("com.cringe-chain.pac")
            self.assertEqual([("local.pac-server", 8899)], found)


class PreflightTest(unittest.TestCase):
    def test_stops_when_service_reads_another_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(pathlib.Path(tmp))
            with mock.patch.object(safety, "running_config_path",
                                   return_value=pathlib.Path("/opt/homebrew/etc/sing-box/config.json")), \
                 mock.patch.object(safety, "foreign_pac_agents", return_value=[]), \
                 mock.patch.object(safety, "wait_for_port", return_value=False):
                problems = safety.preflight(cfg, "com.cringe-chain.pac", 8822)
            self.assertTrue(any(p.fatal for p in problems))
            self.assertIn("читает", problems[0].text)

    def test_same_path_is_fine(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = make_cfg(pathlib.Path(tmp))
            with mock.patch.object(safety, "running_config_path",
                                   return_value=cfg.local.singbox_config), \
                 mock.patch.object(safety, "foreign_pac_agents", return_value=[]), \
                 mock.patch.object(safety, "wait_for_port", return_value=False):
                self.assertEqual([], safety.preflight(cfg, "com.cringe-chain.pac", 8822))


class ApplyRollbackTest(unittest.TestCase):
    """Тот самый сбой: служба не встала — прежний конфиг обязан вернуться."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = make_cfg(self.root)
        self.cfg.local.singbox_config.parent.mkdir(parents=True)
        self.previous = '{"пометка": "прежний рабочий конфиг"}'
        self.cfg.local.singbox_config.write_text(self.previous)
        self.restarts = []

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self):
        return mock.Mock(config=None, dry_run=False, force=False, json=False)

    def test_failed_start_restores_previous_config(self):
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(safety, "preflight", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(True, "")), \
             mock.patch.object(safety, "wait_for_port", return_value=False), \
             mock.patch.object(cli.system, "brew_service",
                               side_effect=lambda a, *rest, **kw: self.restarts.append(a) or []):
            rc = cli.cmd_apply(self._args())

        self.assertEqual(1, rc, "неудачный apply обязан вернуть ненулевой код")
        self.assertEqual(self.previous, self.cfg.local.singbox_config.read_text(),
                         "прежний конфиг должен лежать на диске после отката")
        self.assertEqual(["restart", "restart"], self.restarts,
                         "служба должна быть поднята обратно на прежнем конфиге")

    def test_successful_apply_keeps_new_config(self):
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(safety, "preflight", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(True, "")), \
             mock.patch.object(safety, "wait_for_port", return_value=True), \
             mock.patch.object(cli.system, "brew_service", return_value=[]):
            rc = cli.cmd_apply(self._args())
        self.assertEqual(0, rc)
        written = json.loads(self.cfg.local.singbox_config.read_text())
        self.assertEqual("direct", written["route"]["final"])

    def test_bad_config_never_touches_the_service(self):
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(safety, "preflight", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(False, "битый json")), \
             mock.patch.object(cli.system, "brew_service",
                               side_effect=lambda a, *r, **k: self.restarts.append(a) or []):
            rc = cli.cmd_apply(self._args())
        self.assertEqual(1, rc)
        self.assertEqual([], self.restarts, "службу трогать нельзя, если конфиг не принят")
        self.assertEqual(self.previous, self.cfg.local.singbox_config.read_text())

    def test_fatal_preflight_changes_nothing(self):
        stop = [safety.Problem(safety.STOP, "служба читает другой файл")]
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(safety, "preflight", return_value=stop), \
             mock.patch.object(cli.system, "brew_service",
                               side_effect=lambda a, *r, **k: self.restarts.append(a) or []):
            rc = cli.cmd_apply(self._args())
        self.assertEqual(3, rc)
        self.assertEqual([], self.restarts)
        self.assertEqual(self.previous, self.cfg.local.singbox_config.read_text())


class OnOrderTest(unittest.TestCase):
    """Система не должна переключаться на мёртвый прокси."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_cfg(pathlib.Path(self.tmp.name))
        self.cfg.local.singbox_config.parent.mkdir(parents=True)
        self.cfg.local.singbox_config.write_text("{}")

    def tearDown(self):
        self.tmp.cleanup()

    def test_dead_service_leaves_system_untouched(self):
        touched = []
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(safety, "preflight", return_value=[]), \
             mock.patch.object(safety, "wait_for_port", return_value=False), \
             mock.patch.object(cli.system, "brew_service", return_value=[]), \
             mock.patch.object(cli.system, "set_pac",
                               side_effect=lambda *a, **k: touched.append("pac")), \
             mock.patch.object(cli.system, "setenv",
                               side_effect=lambda *a, **k: touched.append("env")), \
             mock.patch.object(cli.pacserver, "install",
                               side_effect=lambda *a, **k: touched.append("agent")):
            rc = cli.cmd_on(mock.Mock(config=None, dry_run=False, force=False, json=False))
        self.assertEqual(1, rc)
        self.assertEqual([], touched,
                         "ни агент, ни PAC, ни переменные не должны быть тронуты")


if __name__ == "__main__":
    unittest.main()


class ReleaseOrderTest(unittest.TestCase):
    """Отцеплять систему надо в строгом порядке, иначе остаётся окно без сети."""

    def test_env_vars_go_before_system_proxy(self):
        order = []
        with mock.patch.object(cli.system, "unsetenv",
                               side_effect=lambda v, **k: order.append(("env", v))), \
             mock.patch.object(cli.system, "network_services", return_value=["Wi-Fi"]), \
             mock.patch.object(cli.system, "disable_proxy",
                               side_effect=lambda s, **k: order.append(("proxy", s))):
            cli._release_system()
        kinds = [k for k, _ in order]
        self.assertLess(kinds.index("proxy"), len(kinds))
        self.assertTrue(all(k == "env" for k in kinds[:kinds.index("proxy")]),
                        "переменные должны сниматься до системного прокси")

    def test_lowercase_variants_are_cleared_too(self):
        cleared = []
        with mock.patch.object(cli.system, "unsetenv",
                               side_effect=lambda v, **k: cleared.append(v)), \
             mock.patch.object(cli.system, "network_services", return_value=[]), \
             mock.patch.object(cli.system, "disable_proxy"):
            cli._release_system()
        for v in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
            self.assertIn(v, cleared)


class RescueTest(unittest.TestCase):
    """Аварийная команда обязана работать в худшем случае, а не в лучшем."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.cfg = make_cfg(self.root)
        self.cfg.local.singbox_config.parent.mkdir(parents=True)
        self.cfg.local.singbox_config.write_text('{"битый": true}')
        self.good = self.cfg.local.singbox_config.with_suffix(".json.backup-20261022-200000")
        self.good.write_text('{"рабочий": true}')

    def tearDown(self):
        self.tmp.cleanup()

    def _args(self):
        return mock.Mock(config=None, dry_run=False, force=False, json=False)

    def test_system_is_released_even_if_settings_are_broken(self):
        released = []
        with mock.patch.object(cli, "_load", side_effect=cfgmod.ConfigError("файл битый")), \
             mock.patch.object(cli.system, "unsetenv",
                               side_effect=lambda v, **k: released.append(v)), \
             mock.patch.object(cli.system, "network_services", return_value=["Wi-Fi"]), \
             mock.patch.object(cli.system, "disable_proxy",
                               side_effect=lambda s, **k: released.append(s)), \
             mock.patch.object(cli.pacserver, "uninstall", return_value=[]):
            rc = cli.cmd_rescue(self._args())
        self.assertEqual(1, rc)
        self.assertIn("HTTPS_PROXY", released)
        self.assertIn("Wi-Fi", released)

    def test_falls_back_to_a_backup_that_actually_starts(self):
        tried = []

        def came_up(cfg, seconds=25):
            text = cfg.local.singbox_config.read_text()
            tried.append(text)
            return ("рабочий" in text, "оба порта слушают" if "рабочий" in text else "порты молчат")

        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(cli.system, "unsetenv"), \
             mock.patch.object(cli.system, "network_services", return_value=[]), \
             mock.patch.object(cli.system, "disable_proxy"), \
             mock.patch.object(cli.pacserver, "uninstall", return_value=[]), \
             mock.patch.object(cli.system, "brew_service", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(True, "")), \
             mock.patch.object(safety, "service_came_up", side_effect=came_up):
            rc = cli.cmd_rescue(self._args())

        self.assertEqual(0, rc)
        self.assertIn("рабочий", self.cfg.local.singbox_config.read_text(),
                      "на диске должен остаться конфиг, на котором служба встала")
        self.assertEqual(2, len(tried), "сначала текущий, потом резерв")

    def test_reports_failure_when_nothing_starts(self):
        with mock.patch.object(cli, "_load", return_value=self.cfg), \
             mock.patch.object(cli.system, "unsetenv"), \
             mock.patch.object(cli.system, "network_services", return_value=[]), \
             mock.patch.object(cli.system, "disable_proxy"), \
             mock.patch.object(cli.pacserver, "uninstall", return_value=[]), \
             mock.patch.object(cli.system, "brew_service", return_value=[]), \
             mock.patch.object(safety, "config_is_valid", return_value=(True, "")), \
             mock.patch.object(safety, "service_came_up", return_value=(False, "порты молчат")):
            rc = cli.cmd_rescue(self._args())
        self.assertEqual(1, rc)
