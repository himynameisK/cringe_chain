"""Пробный запуск: доказать, что конфиг поднимается, ДО того как отдать его службе.

Зачем это существует. `sing-box check` проверяет форму конфига и молча
принимает такой, с которым служба падает при старте: реальный случай —
`log.output` в несуществующем каталоге, `check` доволен, запуск даёт
`FATAL start logger: no such file or directory`. Проверка синтаксиса и
работающая служба — разные утверждения, и второе доказывается только
запуском.

Поэтому здесь нет ни одной проверки вида «а вдруг». Есть одно действие:
взять ровно тот конфиг, который собираемся применить, поднять на нём
настоящий sing-box на черновых портах, дождаться, пока он займёт их, и
погасить. Если это получилось — конфиг заведомо рабочий. Если нет — живую
службу мы не трогали вовсе.

Перечислять причины отказа не нужно: любая из них, известная и неизвестная,
проявляется одинаково — порт не занят.
"""
from __future__ import annotations

import copy
import json
import pathlib
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class BootResult:
    ok: bool
    reason: str
    log: str = ""

    def __bool__(self) -> bool:
        return self.ok


def free_port() -> int:
    """Порт, свободный прямо сейчас. Гонка здесь безвредна: занятость — тоже отказ."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_bound(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


def rehearsal_config(cfg_dict: dict) -> tuple[dict, list[int]]:
    """Копия конфига, в которой подменены ТОЛЬКО порты.

    Больше ничего трогать нельзя, и это выстрадано: первая версия подменяла
    ещё и log.output — то самое поле, из-за которого служба и падала. Проба
    радостно поднималась на подменённом пути и пропускала ровно тот сбой,
    ради которого писалась.

    Правило: проба отличается от применяемого конфига минимально, и только
    там, где иначе поспорит с живой службой за ресурс. Всё остальное —
    пути, права, параметры — проверяется ровно в том виде, в каком поедет
    в работу.
    """
    probe = copy.deepcopy(cfg_dict)
    ports = []
    for inbound in probe.get("inbounds", []):
        port = free_port()
        inbound["listen_port"] = port
        ports.append(port)
    return probe, ports


def boot_test(cfg_dict: dict, singbox: str = "sing-box", seconds: float = 12.0) -> BootResult:
    """Поднять настоящий sing-box на этом конфиге и убедиться, что он занял порты."""
    with tempfile.TemporaryDirectory(prefix="cringe-rehearsal-") as tmp:
        tmpdir = pathlib.Path(tmp)
        probe, ports = rehearsal_config(cfg_dict)
        if not ports:
            return BootResult(False, "в конфиге нет ни одного inbound — нечего поднимать")
        path = tmpdir / "config.json"
        path.write_text(json.dumps(probe, indent=2, ensure_ascii=False))

        try:
            proc = subprocess.Popen(
                [singbox, "run", "-c", str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
        except FileNotFoundError:
            return BootResult(False, f"бинарь {singbox} не найден")
        except OSError as exc:
            return BootResult(False, f"запустить не удалось: {exc}")

        try:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    out = (proc.stdout.read() if proc.stdout else "") or ""
                    return BootResult(False, "процесс завершился, не заняв порты",
                                      out.strip()[-800:])
                if all(port_bound(p) for p in ports):
                    return BootResult(True, f"поднялся и занял порты {ports}")
                time.sleep(0.2)
            return BootResult(False, f"за {seconds:g} с не занял порты {ports}")
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
