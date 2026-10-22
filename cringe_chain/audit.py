"""Разбор журнала sing-box: какие хосты ушли мимо туннеля и почему.

Весь разбор — чистые функции над текстом; файл открывает одна `audit_file`.
Так проверку можно гонять на тестовых строках, не заводя ни конфига, ни лога.

Правила берутся из ЖИВОГО конфига sing-box, а не из списка в коде: список
в коде расходится с конфигом молча, и тогда отчёт «всё чисто» ничего не стоит.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .config import ConfigError

__all__ = [
    "Connection",
    "Leak",
    "LeakReport",
    "audit_file",
    "covered",
    "find_leaks",
    "looks_ours",
    "parse_log",
    "tunnel_marks",
    "tunnel_rules",
]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Типы outbound'ов, которые туннелем не являются. Всё прочее — наше плечо,
# каким бы протоколом оно ни было; так новый протокол не придётся вписывать сюда.
_NOT_TUNNEL = frozenset({"direct", "block", "dns"})

# Тег прямого выхода. В sing-box это имя из конфига, но по соглашению —
# "direct"; журнал других примет прямого соединения не даёт.
_DIRECT_TAG = "direct"

_TS_FMT = "%Y-%m-%d %H:%M:%S"


# ───────────────────────── правила из конфига ─────────────────────────

def _as_list(value: object) -> list:
    """Поле правила списком, чем бы оно ни было записано.

    sing-box принимает такие поля и строкой, и списком. Голую строку надо
    завернуть: перебор по ней даёт отдельные буквы, и из `ip_cidr` молча
    выходят сети вида 0.0.0.2/32, а правило превращается в ничто.
    """
    if isinstance(value, str):
        return [value]
    return list(value) if isinstance(value, (list, tuple)) else []


def tunnel_rules(singbox_cfg: dict) -> tuple[set[str], list[IPNetwork]]:
    """Что ДОЛЖНО идти в туннель: суффиксы доменов и подсети из правил маршрута.

    Берём только правила, ведущие в туннельный outbound: правило на direct
    описывает ровно обратное — что туннель обходит.
    """
    if not isinstance(singbox_cfg, dict):
        raise ConfigError("конфиг sing-box: ожидается объект JSON")
    outbounds = singbox_cfg.get("outbounds")
    if not isinstance(outbounds, list):
        # Без outbounds мы не знаем ни одного туннельного тега, и проверка
        # выдала бы «утечек нет» на любом логе. Лучше громкая ошибка.
        raise ConfigError("конфиг sing-box: нет списка outbounds — проверять нечего")

    tags = {
        o["tag"] for o in outbounds
        if isinstance(o, dict) and o.get("tag") and o.get("type") not in _NOT_TUNNEL
    }

    suffixes: set[str] = set()
    cidrs: list[IPNetwork] = []
    route = singbox_cfg.get("route")
    rules = route.get("rules") if isinstance(route, dict) else None
    for rule in _as_list(rules):
        if not isinstance(rule, dict) or rule.get("outbound") not in tags:
            continue
        for key in ("domain_suffix", "domain"):
            suffixes.update(
                s.lstrip(".").lower()
                for s in _as_list(rule.get(key))
                if isinstance(s, str) and s.strip(".")
            )
        for net in _as_list(rule.get("ip_cidr")):
            try:
                cidrs.append(ipaddress.ip_network(net))
            except (ValueError, TypeError):
                continue  # правила бывают с мусором; из-за одного не падаем
    return suffixes, cidrs


def covered(host: str, suffixes: set[str], cidrs: list[IPNetwork]) -> bool:
    """Покрыт ли хост правилом: по суффиксу домена либо по подсети.

    Хост в журнале бывает голым адресом — тогда работает только вторая половина.
    """
    host = host.lower().rstrip(".")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return any(addr in net for net in cidrs)
    return any(host == s or host.endswith("." + s) for s in suffixes)


def tunnel_marks(suffixes: set[str]) -> set[str]:
    """Приметы «нашего» хоста: вторые уровни доменов из правил, от 4 букв.

    Только двухсоставные суффиксы. Из многосоставного (вида
    `sub.service.example.com`) приметой стала бы `service` — слишком общее
    слово, и в подозреваемые попала бы половина интернета, включая чужие CDN.
    Короткие метки отбрасываем по той же причине.
    """
    return {
        s.split(".")[0] for s in suffixes
        if s.count(".") == 1 and len(s.split(".")[0]) >= 4
    }


def looks_ours(host: str, marks: set[str]) -> bool:
    """Похож ли хост на наш.

    Примета должна стоять ОТДЕЛЬНОЙ долей имени (или частью доли через дефис),
    а не подстрокой: иначе примета `claude` ловит `claudecompanyunrelated.…`,
    к нам отношения не имеющий.
    """
    for label in host.lower().split("."):
        if label in marks or any(part in marks for part in label.split("-")):
            return True
    return False


# ───────────────────────── разбор журнала ─────────────────────────

@dataclass(frozen=True)
class Connection:
    """Одно исходящее соединение из журнала."""
    ts: str
    cid: str
    tag: str
    host: str


# Общее начало строки: зона, отметка времени, уровень, номер соединения.
_STAMP = r"^\S+ (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \w+ \[(\d+) "

_OPENED_RE = re.compile(
    _STAMP + r"[^]]*\] outbound/[\w-]+\[([^\]]+)\]: "
             r"outbound (?:packet )?connection to (.+):\d+$"
)
_FAILED_RE = re.compile(
    _STAMP + r"[^]]*\] connection: open connection to (.+?):\d+ "
             r"using outbound/[\w-]+\[([^\]]+)\]"
)


def _parse_line(line: str) -> Connection | None:
    """Разобрать строку журнала. Чужие и битые строки — None, без шума."""
    m = _OPENED_RE.match(line)
    if m:
        ts, cid, tag, host = m.group(1), m.group(2), m.group(3), m.group(4)
    else:
        m = _FAILED_RE.match(line)
        if not m:
            return None
        ts, cid, host, tag = m.group(1), m.group(2), m.group(3), m.group(4)
    return Connection(ts=ts, cid=cid, tag=tag, host=host.lower())


def parse_log(lines: Iterable[str]) -> list[Connection]:
    """Соединения из журнала, по одному на соединение.

    Одно соединение попадает в журнал ДВУМЯ строками: INFO при открытии и
    ERROR при провале, с одним номером в скобках. Складываем по паре
    (номер, хост) — иначе хост с падающим DNS удваивается и возглавляет отчёт.
    """
    out: list[Connection] = []
    seen: set[tuple[str, str]] = set()
    for line in lines:
        conn = _parse_line(line.rstrip())
        if conn is None:
            continue
        key = (conn.cid, conn.host)
        if key in seen:
            continue
        seen.add(key)
        out.append(conn)
    return out


# ───────────────────────── поиск утечек ─────────────────────────

@dataclass(frozen=True)
class Leak:
    """Хост, ушедший напрямую, с числом попаданий и границами периода."""
    host: str
    count: int
    first: str
    last: str


@dataclass(frozen=True)
class LeakReport:
    stale: list[Leak]
    missing: list[Leak]
    explained: list[Leak]
    total: int
    direct: int
    first_ts: str | None
    last_ts: str | None

    @property
    def ok(self) -> bool:
        """Расхождений нет. `explained` — история, она на вердикт не влияет."""
        return not self.stale and not self.missing


def _after(ts: str, moment: datetime) -> bool:
    """Позже ли отметка журнала, чем правка конфига.

    Неразбираемую отметку считаем свежей: пропущенная утечка дороже лишней
    строки в отчёте.
    """
    try:
        return datetime.strptime(ts, _TS_FMT) > moment
    except ValueError:
        return True


def _sorted(leaks: list[Leak]) -> list[Leak]:
    """Частые сверху; при равенстве — по имени, чтобы отчёт не плясал."""
    return sorted(leaks, key=lambda leak: (-leak.count, leak.host))


def find_leaks(
    connections: Iterable[Connection],
    suffixes: set[str],
    cidrs: list[IPNetwork],
    marks: set[str],
    config_mtime: datetime | None,
) -> LeakReport:
    """Разложить прямые соединения по трём корзинам.

    stale     — правило есть, но хост ушёл мимо ПОЗЖЕ правки конфига:
                sing-box не перечитал конфиг, лечится перезапуском;
    explained — то же, но РАНЬШЕ правки: правило добавили потом, это история;
    missing   — похож на наш по приметам, а правила нет. Вот это утечка.
    """
    if config_mtime is not None and config_mtime.tzinfo is not None:
        # Отметки журнала — местное время без зоны; приводим к нему,
        # иначе сравнение aware с naive падает TypeError.
        config_mtime = config_mtime.astimezone().replace(tzinfo=None)

    total = direct = 0
    stamps: list[str] = []
    counts: dict[str, int] = {}
    bounds: dict[str, list[str]] = {}

    for conn in connections:
        total += 1
        stamps.append(conn.ts)
        if conn.tag != _DIRECT_TAG:
            continue
        direct += 1
        counts[conn.host] = counts.get(conn.host, 0) + 1
        seen = bounds.setdefault(conn.host, [conn.ts, conn.ts])
        # Отметка «YYYY-MM-DD HH:MM:SS» сортируется как строка, поэтому
        # min/max верны даже если строки в журнале перепутаны местами.
        seen[0] = min(seen[0], conn.ts)
        seen[1] = max(seen[1], conn.ts)

    stale: list[Leak] = []
    missing: list[Leak] = []
    explained: list[Leak] = []
    for host, count in counts.items():
        first, last = bounds[host]
        leak = Leak(host=host, count=count, first=first, last=last)
        if covered(host, suffixes, cidrs):
            # Без времени правки отличить «не перечитал» от «правило добавили
            # позже» нечем — считаем всё свежим, чтобы не замолчать утечку.
            if config_mtime is None or _after(last, config_mtime):
                stale.append(leak)
            else:
                explained.append(leak)
        elif looks_ours(host, marks):
            missing.append(leak)

    return LeakReport(
        stale=_sorted(stale),
        missing=_sorted(missing),
        explained=_sorted(explained),
        total=total,
        direct=direct,
        first_ts=min(stamps) if stamps else None,
        last_ts=max(stamps) if stamps else None,
    )


def audit_file(
    singbox_cfg: dict,
    log_path: Path | str,
    config_mtime: datetime | None,
) -> LeakReport:
    """Прочитать журнал и выдать отчёт. Единственная функция, трогающая диск.

    Отсутствие или нечитаемость журнала — обычный OSError: что с этим делать,
    решает вызывающий.
    """
    suffixes, cidrs = tunnel_rules(singbox_cfg)
    marks = tunnel_marks(suffixes)
    # errors="replace": в журнал попадают байты из чужих ответов, и падать
    # на одном битом символе посреди гигабайта лога незачем.
    with open(log_path, encoding="utf-8", errors="replace") as fh:
        connections = parse_log(fh)
    return find_leaks(connections, suffixes, cidrs, marks, config_mtime)
