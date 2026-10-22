"""Проверки живой сети: что на самом деле происходит на пути до цели.

Проверяем внешними `curl`, `nc` и `ping`, а не библиотеками питона, потому что
интересует путь, которым ходят приложения: системный прокси, переменные
окружения, резолвер. Библиотечный сокет пошёл бы другой дорогой и ответил бы
не про ту сеть, которую чиним.

Функции возвращают данные и ничего не печатают: печать — дело вызывающего.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

# Нет ответа — отдельное значение, которое ни с одним кодом HTTP не спутать.
NO_ANSWER = "---"

# Куда спросить свой внешний адрес. Второй — запасной: первый временами молчит.
IP_ECHO = ("http://ifconfig.me/ip", "http://icanhazip.com")

# Размеры IP-пакета для поиска путевого MTU, от обычного к заведомо узкому.
MTU_SIZES = (1500, 1472, 1420, 1400, 1380, 1360, 1340, 1300, 1280, 1200, 1100, 1028)

# Заголовки IP (20) + ICMP (8): ping задаёт размер полезной нагрузки, а не пакета.
_ICMP_OVERHEAD = 28


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Запустить команду с жёстким потолком по времени.

    Таймаут нужен поверх таймаутов самих утилит: зависший `nc` или `curl`
    в непроходящей сети иначе вешает весь прогон проверок.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        # Отсутствие утилиты и зависание — для вызывающего одно и то же:
        # ответа нет. Разбирать их по-разному смысла не имеет.
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr=str(exc))


@dataclass(frozen=True)
class PortCheck:
    """Доступность одного TCP-порта с текущего пути."""
    host: str
    port: int
    open: bool
    detail: str


def port_open(host: str, port: int, timeout: int = 6) -> PortCheck:
    """Прощупать порт TCP-коннектом.

    Три исхода, а не два: «отказ» значит, что до хоста дошли и там никого,
    «не доходит» — что путь режут. Лечатся они по-разному, поэтому исход
    кладём в detail, а не схлопываем в False.
    """
    r = _run(["nc", "-G", str(timeout), "-z", "-v", host, str(port)], timeout=timeout + 5)
    # nc пишет вердикт в stderr; последняя строка — про последнюю попытку.
    out = (r.stderr or r.stdout).strip()
    last = out.splitlines()[-1].strip() if out else ""
    low = last.lower()
    if "succeeded" in low:
        return PortCheck(host, port, True, "открыт")
    if "refused" in low:
        return PortCheck(host, port, False, "закрыт (отказ)")
    if "timed out" in low or r.returncode == 124:
        return PortCheck(host, port, False, "не доходит (таймаут)")
    return PortCheck(host, port, False, last or "нет ответа от nc")


def _curl(args: list[str], proxy: str | None, timeout: int, url: str) -> str:
    """Общая часть всех запросов curl.

    `--noproxy ''` обязателен: без него curl подхватит HTTP_PROXY/HTTPS_PROXY
    из окружения, и проверка соврёт — покажет путь через прокси там, где мы
    просили прямой, или наоборот. Прокси задаём только явным `--proxy`.
    """
    cmd = ["curl", "-s", "--noproxy", "", "--max-time", str(timeout)]
    if proxy:
        cmd += ["--proxy", proxy]
    cmd += args
    cmd.append(url)
    return _run(cmd, timeout=timeout + 5).stdout.strip()


def http_code(url: str, proxy: str | None = None, timeout: int = 25) -> str:
    """Код ответа строкой, NO_ANSWER — если ответа не было.

    Отдельно гасим "000": так curl сообщает, что ответа нет вовсе (не дошли,
    таймаут, прокси отказал). Это не код HTTP, и пропускать его наружу нельзя —
    в отчёте он выглядел бы как ответ сервера.
    """
    got = _curl(["-o", "/dev/null", "-w", "%{http_code}"], proxy, timeout, url)
    return NO_ANSWER if got in ("", "000") else got


def exit_ip(proxy: str | None = None, timeout: int = 20) -> str | None:
    """Внешний адрес, с которого нас видят. None — если не ответил никто."""
    for url in IP_ECHO:
        got = _curl([], proxy, timeout, url)
        if got:
            # Эхо-сервисы иногда отдают адрес с переводом строки или пробелами.
            return got.split()[0]
    return None


@dataclass(frozen=True)
class Trace:
    """Что получатель запроса думает о его источнике."""
    ip: str | None
    loc: str | None
    colo: str | None
    raw: dict[str, str] = field(default_factory=dict)


def trace(url: str, proxy: str | None = None, timeout: int = 25) -> Trace:
    """Запросить у получателя его мнение о нас: <url>/cdn-cgi/trace.

    Это главная проверка пакета: она отвечает не тем, что мы думаем о своём
    конфиге, а тем, что о нас думает получатель. Конфиг может быть собран
    верно и при этом не применяться — цепочка молча пошла мимо, прокси сняли,
    приложение запомнило старые переменные. Здесь видно ip и страну, которые
    реально приехали на ту сторону.
    """
    body = _curl([], proxy, timeout, url.rstrip("/") + "/cdn-cgi/trace")
    raw = dict(
        line.split("=", 1) for line in body.splitlines() if "=" in line
    )
    return Trace(ip=raw.get("ip"), loc=raw.get("loc"), colo=raw.get("colo"), raw=raw)


@dataclass(frozen=True)
class PathMtu:
    """Путевой MTU: наибольший размер пакета, прошедший без фрагментации."""
    best: int
    tried: dict[int, bool] = field(default_factory=dict)

    @property
    def safe_mss(self) -> int:
        """MSS с запасом на заголовки TCP/IP. 0 — если мерить не удалось."""
        return self.best - 40 if self.best else 0


def path_mtu(host: str, timeout_ms: int = 2500) -> PathMtu:
    """Найти путевой MTU: ICMP с запретом фрагментации, от крупного к мелкому.

    Узкий путь не ломает соединение, а рвёт только крупные ответы — и выглядит
    это как случайные зависания, а не как ошибка. best == 0 значит, что ICMP
    по этому пути режут и мерить так нельзя (а не что MTU нулевой).
    """
    tried: dict[int, bool] = {}
    best = 0
    for size in MTU_SIZES:
        payload = size - _ICMP_OVERHEAD
        ok = False
        for _ in range(3):  # ICMP бывает ограничен по частоте — одной попытки мало
            r = _run(
                ["ping", "-D", "-s", str(payload), "-c", "1", "-W", str(timeout_ms), host],
                timeout=timeout_ms / 1000 + 5,
            )
            if "1 packets received" in r.stdout or "1 received" in r.stdout:
                ok = True
                break
        tried[size] = ok
        if ok and size > best:
            best = size
    return PathMtu(best=best, tried=tried)
