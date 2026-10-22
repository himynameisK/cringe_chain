"""Раздатчик PAC-файла: launch-агент с простым http.server.

Системе мы называем адрес вида http://127.0.0.1:<порт>/<имя>.pac, и кто-то
должен по нему отвечать. Файла на диске мало: macOS читает PAC по сети.

Раздатчик слушает ТОЛЬКО 127.0.0.1 — наружу список доменов не уходит.
Файл он читает с диска на каждый запрос, поэтому после `apply` его
перезапускать не нужно: новый список отдаётся сразу.
"""
from __future__ import annotations

import pathlib
import plistlib
import sys
import urllib.parse

from .config import Config, ConfigError
from .system import run, wait_for_port

LABEL = "com.cringe-chain.pac"


def plist_path() -> pathlib.Path:
    return pathlib.Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"


def endpoint(cfg: Config) -> tuple[str, int, str]:
    """Разобрать pac_url на хост, порт и имя файла. Ошибка — внятная."""
    parsed = urllib.parse.urlparse(cfg.local.pac_url)
    if parsed.scheme != "http" or not parsed.port:
        raise ConfigError(
            f"local.pac_url={cfg.local.pac_url!r}: нужен вид http://127.0.0.1:<порт>/<имя>.pac"
        )
    if parsed.hostname not in ("127.0.0.1", "localhost"):
        raise ConfigError(
            f"local.pac_url: раздатчик слушает только петлю, а в адресе {parsed.hostname!r}"
        )
    name = pathlib.PurePosixPath(parsed.path).name
    if not name:
        raise ConfigError("local.pac_url: в адресе нет имени файла")
    return parsed.hostname, parsed.port, name


def pac_file(cfg: Config) -> pathlib.Path:
    """Куда класть файл, чтобы раздатчик отдал его по заявленному адресу."""
    return cfg.local.pac_dir / endpoint(cfg)[2]


def _plist(cfg: Config) -> dict:
    host, port, _ = endpoint(cfg)
    return {
        "Label": LABEL,
        "ProgramArguments": [
            sys.executable, "-m", "http.server", str(port),
            "--bind", host, "--directory", str(cfg.local.pac_dir),
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
    }


def install(cfg: Config, dry_run: bool = False) -> list[str]:
    """Положить агента и поднять его. Повторный вызов безопасен."""
    path, uid = plist_path(), run(["id", "-u"])
    data = _plist(cfg)
    cmds = [
        f"записать {path}",
        f"launchctl bootout gui/{uid}/{LABEL}  (если уже загружен)",
        f"launchctl bootstrap gui/{uid} {path}",
    ]
    if dry_run:
        return cmds
    cfg.local.pac_dir.mkdir(parents=True, exist_ok=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        plistlib.dump(data, fh)
    run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
    run(["launchctl", "bootstrap", f"gui/{uid}", str(path)])
    return cmds


def uninstall(dry_run: bool = False) -> list[str]:
    uid = run(["id", "-u"])
    cmds = [f"launchctl bootout gui/{uid}/{LABEL}"]
    if not dry_run:
        run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
    return cmds


def state(cfg: Config) -> str:
    """Отвечает ли раздатчик на самом деле. Загруженный агент — ещё не ответ."""
    try:
        _, port, _ = endpoint(cfg)
    except ConfigError as exc:
        return f"адрес не разобран: {exc}"
    if not plist_path().exists():
        return "агент не установлен"
    if not wait_for_port(port, 1):
        return f"порт {port} молчит"
    if not pac_file(cfg).exists():
        return f"порт слушает, но файла {pac_file(cfg).name} нет — нужен apply"
    return f"раздаёт на порту {port}"
