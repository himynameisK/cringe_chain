"""Предохранители: проверки до изменений и откат конфига при неудаче.

Модуль появился после реального сбоя 22.10.2026. Цепочка была такая:
apply записал конфиг, в котором журнал указывал на НЕСУЩЕСТВУЮЩИЙ каталог;
sing-box не смог открыть файл журнала и не стартовал; порт 2080 остался
мёртвым, а переменная HTTPS_PROXY продолжала слать туда весь трафик
консольных программ — сети не стало совсем. Откат не помог, потому что
возвращал настройки системы, но не файл конфига: причина оставалась на диске.

Отсюда три правила, которые держит этот модуль:
  1. не писать туда, откуда никто не читает;
  2. любое изменение конфига — транзакция с резервом и возвратом;
  3. система переключается на прокси только после того, как он ответил.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import plistlib
import re
import subprocess
from dataclasses import dataclass

from .config import Config
from .system import run, wait_for_port

STOP, WARN = "stop", "warn"
BACKUPS_KEPT = 10


@dataclass(frozen=True)
class Problem:
    level: str
    text: str
    hint: str = ""

    @property
    def fatal(self) -> bool:
        return self.level == STOP


def running_config_path() -> pathlib.Path | None:
    """С каким --config реально работает запущенный sing-box.

    Путь в службе Homebrew прошит, и если настройки указывают на другой файл,
    apply запишет его впустую — служба продолжит читать старый. Именно так
    первый заход и прошёл «успешно», ничего не изменив.
    """
    try:
        out = subprocess.run(["ps", "-axo", "command="], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if "sing-box" not in line or "grep" in line:
            continue
        m = re.search(r"(?:--config|-c)\s+(\S+)", line)
        if m:
            return pathlib.Path(m.group(1))
    return None


def foreign_pac_agents(our_label: str) -> list[tuple[str, int]]:
    """Чужие launch-агенты, раздающие PAC. Два таких агента = гонка за системную настройку."""
    found = []
    agents = pathlib.Path.home() / "Library/LaunchAgents"
    if not agents.is_dir():
        return found
    for plist in sorted(agents.glob("*.plist")):
        try:
            with open(plist, "rb") as fh:
                data = plistlib.load(fh)
        except (OSError, plistlib.InvalidFileException):
            continue
        label = data.get("Label", "")
        if label == our_label:
            continue
        args = [str(a) for a in data.get("ProgramArguments", [])]
        if not any("http.server" in a for a in args):
            continue
        port = next((int(a) for a in args if a.isdigit() and 1 <= int(a) <= 65535), 0)
        serves_pac = any(
            pathlib.Path(a).is_dir() and any(pathlib.Path(a).glob("*.pac"))
            for a in args if a.startswith("/")
        )
        if serves_pac:
            found.append((label, port))
    return found


def preflight(cfg: Config, our_label: str, pac_port: int) -> list[Problem]:
    """Что проверяем ДО того, как что-либо менять."""
    out: list[Problem] = []

    live = running_config_path()
    if live is not None and live.resolve() != cfg.local.singbox_config.resolve():
        out.append(Problem(
            STOP,
            f"служба читает {live}, а настройки велят писать в {cfg.local.singbox_config}",
            "приведи local.singbox_config к пути, который читает служба, "
            "иначе apply запишет файл, который никто не откроет",
        ))

    for label, port in foreign_pac_agents(our_label):
        out.append(Problem(
            WARN,
            f"на машине есть чужой раздатчик PAC: {label} (порт {port or '?'})",
            "две схемы будут спорить за системную настройку; выключи прежнюю",
        ))

    # порт PAC: свой агент на этом шаге ещё не поднят, значит занять его мог
    # только чужой процесс — и тогда наш просто не запустится
    if wait_for_port(pac_port, 1):
        known = {port for _, port in foreign_pac_agents(our_label)}
        out.append(Problem(
            WARN,
            f"порт {pac_port} уже занят"
            + (" чужим раздатчиком PAC" if pac_port in known else " каким-то процессом"),
            "выбери другой порт в local.pac_url или останови того, кто его держит",
        ))
    return out


def ensure_dirs(cfg: Config, pac_file: pathlib.Path) -> list[pathlib.Path]:
    """Создать ВСЕ каталоги, куда пакет будет писать.

    Каталог журнала забыли ровно один раз — и это стоило двух с половиной
    часов без сети. sing-box не создаёт его сам и просто не стартует.
    """
    made = []
    for path in (cfg.local.singbox_config.parent, pac_file.parent, cfg.local.singbox_log.parent):
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            made.append(path)
    return made


def config_is_valid(path: pathlib.Path, singbox: str = "sing-box") -> tuple[bool, str]:
    """Спросить сам sing-box, примет ли он файл. Дешевле, чем узнать это перезапуском."""
    try:
        r = subprocess.run([singbox, "check", "-c", str(path)],
                           capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return True, "бинарь sing-box не найден, проверку пропускаю"
    except (OSError, subprocess.SubprocessError) as exc:
        return True, f"проверку выполнить не удалось: {exc}"
    return r.returncode == 0, (r.stderr or r.stdout).strip()[:400]


class ConfigSwap:
    """Замена конфига с резервом и возвратом.

    Используется как контекст: если внутри не вызвали commit(), прежний файл
    возвращается на место. Возврат именно ФАЙЛА — то, чего не хватало:
    прошлый откат чинил настройки системы и оставлял причину на диске.
    """

    def __init__(self, path: pathlib.Path, new_text: str, keep: int = BACKUPS_KEPT):
        self.path = path
        self.new_text = new_text
        self.keep = keep
        self.backup: pathlib.Path | None = None
        self.committed = False

    def __enter__(self) -> "ConfigSwap":
        if self.path.exists():
            stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
            self.backup = self.path.with_suffix(self.path.suffix + f".backup-{stamp}")
            self.backup.write_text(self.path.read_text())
            self._prune()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.new_text)
        return self

    def commit(self) -> None:
        self.committed = True

    def restore(self) -> bool:
        """Вернуть прежний файл. True, если было что возвращать."""
        if self.backup is None or not self.backup.exists():
            return False
        self.path.write_text(self.backup.read_text())
        return True

    def __exit__(self, exc_type, exc, tb) -> bool:
        if not self.committed:
            self.restore()
        return False

    def _prune(self) -> None:
        olds = sorted(self.path.parent.glob(self.path.name + ".backup-*"))
        for extra in olds[:-self.keep]:
            try:
                extra.unlink()
            except OSError:
                pass


def latest_backup(path: pathlib.Path) -> pathlib.Path | None:
    olds = sorted(path.parent.glob(path.name + ".backup-*"))
    return olds[-1] if olds else None


def service_came_up(cfg: Config, seconds: int = 25) -> tuple[bool, str]:
    """Служба считается поднятой, только если заняла ОБА порта.

    Проверяем порты, а не код возврата brew: brew сообщает об успехе запуска,
    а не о том, что процесс выжил. В тот раз он отчитался и умер.
    """
    if not wait_for_port(cfg.local.entry_port, seconds):
        return False, f"порт {cfg.local.entry_port} не занят за {seconds} с"
    if not wait_for_port(cfg.local.socks_port, 5):
        return False, f"порт {cfg.local.socks_port} не занят"
    return True, "оба порта слушают"


def log_tail(cfg: Config, lines: int = 12) -> str:
    """Последние строки журнала службы — чтобы не отправлять человека искать их самому."""
    p = cfg.local.singbox_log
    if not p.exists():
        return f"журнала {p} нет вовсе — похоже, служба не смогла его открыть"
    try:
        return "\n".join(p.read_text(errors="replace").splitlines()[-lines:])
    except OSError as exc:
        return f"журнал не читается: {exc}"
