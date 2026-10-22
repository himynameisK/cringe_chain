"""Всё, что дёргает macOS: сетевые службы, системный прокси, brew, launchctl.

У каждой функции, которая что-то меняет, есть dry_run. При dry_run=True она
ничего не выполняет и возвращает те же команды строками. Это единственный
способ проверить операции, меняющие системные настройки: юнит-тестами их не
покрыть — настоящий вызов переставит прокси на машине, где идёт тест.
Возвращаемый список одинаков в обоих режимах, поэтому режим «показать»
действительно описывает режим «сделать», а не похожий на него.
"""
from __future__ import annotations

import shlex
import socket
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path

# Системные утилиты macOS по абсолютным путям: PATH у launchd и у терминала
# разный, а под sudo ещё и урезается.
NETWORKSETUP = "/usr/sbin/networksetup"
LAUNCHCTL = "/bin/launchctl"

# Локальная заглушка для проверки портов. Слушающие службы поднимаем мы сами,
# поэтому проверяем именно петлю, а не адрес из настроек.
LOOPBACK = "127.0.0.1"


def run(cmd: list[str], quiet: bool = True) -> str:
    """Выполнить команду и вернуть stdout. Ошибку при quiet=False — напечатать."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError) as exc:
        if not quiet:
            print(f"    ! {shlex.join(cmd)} -> {exc}")
        return ""
    if r.returncode and not quiet:
        print(f"    ! {shlex.join(cmd)} -> {r.stderr.strip() or r.stdout.strip()}")
    return r.stdout.strip()


def _apply(cmds: list[list[str]], dry_run: bool, quiet: bool = True) -> list[str]:
    """Выполнить набор команд (или только показать) и вернуть их строками."""
    if not dry_run:
        for cmd in cmds:
            run(cmd, quiet=quiet)
    return [shlex.join(cmd) for cmd in cmds]


def network_services() -> list[str]:
    """Имена включённых сетевых служб.

    Прокси в macOS хранится НА СЛУЖБЕ, а не на системе, и основная служба
    меняется сама при подключении туннеля — настройка, поставленная только
    текущей службе, после переключения просто перестаёт применяться. Поэтому
    настройку ставят всем службам сразу.
    """
    out = run([NETWORKSETUP, "-listallnetworkservices"]).splitlines()
    # Первая строка — пояснение про звёздочку, не служба. Отключённые службы
    # помечены звёздочкой: ставить им прокси бессмысленно и шумно в выводе.
    return [s.strip() for s in out[1:] if s.strip() and not s.startswith("*")]


def set_pac(service: str, pac_url: str, dry_run: bool = False) -> list[str]:
    """Включить PAC и снять сплошной прокси.

    PAC и явный web-прокси работают одновременно, и тогда в туннель уходит всё
    подряд: сплошной прокси гасим тем же вызовом, иначе остаётся от прошлого раза.
    """
    return _apply([
        ["sudo", NETWORKSETUP, "-setautoproxyurl", service, pac_url],
        ["sudo", NETWORKSETUP, "-setwebproxystate", service, "off"],
        ["sudo", NETWORKSETUP, "-setsecurewebproxystate", service, "off"],
    ], dry_run, quiet=False)


def set_bypass(service: str, domains: Sequence[str], dry_run: bool = False) -> list[str]:
    """Задать список доменов в обход прокси.

    networksetup перезаписывает список целиком, поэтому передаём его целиком;
    пустой список сбрасывает исключения, что тоже бывает нужно.
    """
    return _apply(
        [["sudo", NETWORKSETUP, "-setproxybypassdomains", service, *domains]],
        dry_run, quiet=False,
    )


def disable_proxy(service: str, dry_run: bool = False) -> list[str]:
    """Вернуть службу к прямому доступу: снять и PAC, и сплошной прокси."""
    return _apply([
        ["sudo", NETWORKSETUP, "-setwebproxystate", service, "off"],
        ["sudo", NETWORKSETUP, "-setsecurewebproxystate", service, "off"],
        ["sudo", NETWORKSETUP, "-setautoproxystate", service, "off"],
    ], dry_run, quiet=False)


def proxy_state(service: str) -> str:
    """Что сейчас стоит у службы: "PAC" | "сплошной прокси" | "выключен".

    PAC проверяем первым: когда включено и то и другое, решает он.
    """
    if "Enabled: Yes" in run([NETWORKSETUP, "-getautoproxyurl", service]):
        return "PAC"
    if "Enabled: Yes" in run([NETWORKSETUP, "-getwebproxy", service]):
        return "сплошной прокси"
    return "выключен"


def brew_service(action: str, name: str, brew: Path, dry_run: bool = False) -> list[str]:
    """Поднять или погасить службу homebrew (start / stop / restart)."""
    return _apply([[str(brew), "services", action, name]], dry_run, quiet=False)


def service_state(name: str, brew: Path) -> str:
    """Состояние службы из `brew services list`, либо "неизвестно"."""
    for line in run([str(brew), "services", "list"]).splitlines():
        parts = line.split()
        if parts and parts[0] == name:
            return parts[1] if len(parts) > 1 else "неизвестно"
    return "неизвестно"


def setenv(var: str, value: str, dry_run: bool = False) -> list[str]:
    """Прописать переменную окружения на уровне сессии входа.

    Её подхватят только приложения, запущенные ПОСЛЕ: уже открытые держат
    свою копию окружения и требуют перезапуска.
    """
    return _apply([[LAUNCHCTL, "setenv", var, value]], dry_run)


def unsetenv(var: str, dry_run: bool = False) -> list[str]:
    """Снять переменную окружения сессии входа."""
    return _apply([[LAUNCHCTL, "unsetenv", var]], dry_run)


def wait_for_port(port: int, seconds: int = 20) -> bool:
    """Дождаться, пока локальный порт начнёт слушать.

    Службы поднимаются не мгновенно, и проверка сразу после старта даёт
    ложное «не запустилось».
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex((LOOPBACK, port)) == 0:
                return True
        time.sleep(0.5)
    return False
