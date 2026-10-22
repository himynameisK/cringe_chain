"""Настройки: единственное место, где живут адреса, порты и списки доменов.

В коде нет ни одного зашитого адреса. Всё приходит отсюда, из TOML-файла,
который лежит вне репозитория (см. config.example.toml).
"""
from __future__ import annotations

import os
import pathlib
import tomllib
from dataclasses import dataclass, field

SHADOWSOCKS = "shadowsocks"
VLESS_REALITY = "vless-reality"
PROTOCOLS = (SHADOWSOCKS, VLESS_REALITY)


class ConfigError(Exception):
    """Настройки не читаются или неполны. Текст пригоден для показа человеку."""


@dataclass(frozen=True)
class Server:
    """Одно звено цепочки.

    detour — имя ПРЕДЫДУЩЕГО звена: соединение к этому серверу пойдёт через него.
    Пустая строка означает «идти напрямую».
    """
    name: str
    host: str
    port: int
    protocol: str
    detour: str = ""
    params: dict = field(default_factory=dict)

    @property
    def is_shadowsocks(self) -> bool:
        return self.protocol == SHADOWSOCKS

    @property
    def is_reality(self) -> bool:
        return self.protocol == VLESS_REALITY


@dataclass(frozen=True)
class Routing:
    """Что уходит в туннель и что обходит прокси стороной."""
    tunnel_domains: tuple[str, ...] = ()
    tunnel_cidrs: tuple[str, ...] = ()
    bypass_domains: tuple[str, ...] = ()
    no_proxy: tuple[str, ...] = ()


@dataclass(frozen=True)
class Local:
    """Пути и порты на этой машине."""
    singbox_config: pathlib.Path
    singbox_log: pathlib.Path
    brew: pathlib.Path
    pac_dir: pathlib.Path
    pac_url: str
    entry_port: int
    socks_port: int
    log_level: str = "info"


@dataclass(frozen=True)
class Config:
    local: Local
    routing: Routing
    servers: tuple[Server, ...]
    path: pathlib.Path | None = None

    def server(self, name: str) -> Server:
        for s in self.servers:
            if s.name == name:
                return s
        known = ", ".join(s.name for s in self.servers) or "ни одного"
        raise ConfigError(f"сервера {name!r} нет в настройках (есть: {known})")

    @property
    def final_server(self) -> Server:
        """Последнее звено — его адрес увидит цель. Это тот, на кого никто не ссылается."""
        if not self.servers:
            raise ConfigError("в настройках нет ни одного сервера")
        referenced = {s.detour for s in self.servers if s.detour}
        tail = [s for s in self.servers if s.name not in referenced]
        if len(tail) != 1:
            names = ", ".join(s.name for s in tail) or "ни одного"
            raise ConfigError(
                "последнее звено цепочки определяется неоднозначно "
                f"(кандидаты: {names}); проверь поля detour"
            )
        return tail[0]


def default_path() -> pathlib.Path:
    """~/.config/cringe-chain/config.toml, либо путь из CRINGE_CHAIN_CONFIG."""
    env = os.environ.get("CRINGE_CHAIN_CONFIG")
    if env:
        return pathlib.Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or (pathlib.Path.home() / ".config")
    return pathlib.Path(base).expanduser() / "cringe-chain" / "config.toml"


def _path(raw: str, key: str) -> pathlib.Path:
    if not isinstance(raw, str) or not raw:
        raise ConfigError(f"{key}: ожидается непустая строка с путём")
    return pathlib.Path(raw).expanduser()


def _tuple(raw, key: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise ConfigError(f"{key}: ожидается список строк")
    return tuple(raw)


def parse(data: dict, path: pathlib.Path | None = None) -> Config:
    """Собрать Config из уже разобранного TOML. Вынесено отдельно ради тестов."""
    if not isinstance(data, dict):
        raise ConfigError("корень файла настроек должен быть таблицей")

    raw_local = data.get("local") or {}
    if not isinstance(raw_local, dict):
        raise ConfigError("секция [local] должна быть таблицей")
    try:
        local = Local(
            singbox_config=_path(raw_local.get("singbox_config", ""), "local.singbox_config"),
            singbox_log=_path(raw_local.get("singbox_log", ""), "local.singbox_log"),
            brew=_path(raw_local.get("brew", ""), "local.brew"),
            pac_dir=_path(raw_local.get("pac_dir", ""), "local.pac_dir"),
            pac_url=raw_local.get("pac_url") or "",
            entry_port=int(raw_local.get("entry_port", 0)),
            socks_port=int(raw_local.get("socks_port", 0)),
            log_level=raw_local.get("log_level", "info"),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"секция [local]: {exc}") from exc
    if not local.pac_url:
        raise ConfigError("local.pac_url не задан")
    for port, key in ((local.entry_port, "entry_port"), (local.socks_port, "socks_port")):
        if not 1 <= port <= 65535:
            raise ConfigError(f"local.{key}: порт вне диапазона 1..65535")

    raw_routing = data.get("routing") or {}
    if not isinstance(raw_routing, dict):
        raise ConfigError("секция [routing] должна быть таблицей")
    routing = Routing(
        tunnel_domains=_tuple(raw_routing.get("tunnel_domains"), "routing.tunnel_domains"),
        tunnel_cidrs=_tuple(raw_routing.get("tunnel_cidrs"), "routing.tunnel_cidrs"),
        bypass_domains=_tuple(raw_routing.get("bypass_domains"), "routing.bypass_domains"),
        no_proxy=_tuple(raw_routing.get("no_proxy"), "routing.no_proxy"),
    )
    if not routing.tunnel_domains and not routing.tunnel_cidrs:
        raise ConfigError(
            "routing: не задано ничего, что должно идти в туннель — "
            "заполни tunnel_domains или tunnel_cidrs"
        )

    raw_servers = data.get("servers") or []
    if not isinstance(raw_servers, list):
        raise ConfigError("секция [[servers]] должна быть списком таблиц")
    servers: list[Server] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_servers, 1):
        if not isinstance(raw, dict):
            raise ConfigError(f"[[servers]] №{i}: должна быть таблицей")
        name = raw.get("name") or ""
        if not name:
            raise ConfigError(f"[[servers]] №{i}: не задано name")
        if name in seen:
            raise ConfigError(f"[[servers]] {name!r}: имя повторяется")
        seen.add(name)
        protocol = raw.get("protocol") or ""
        if protocol not in PROTOCOLS:
            raise ConfigError(
                f"[[servers]] {name!r}: protocol={protocol!r}, "
                f"поддерживаются {' и '.join(PROTOCOLS)}"
            )
        host = raw.get("host") or ""
        if not host:
            raise ConfigError(f"[[servers]] {name!r}: не задан host")
        try:
            port = int(raw.get("port", 0))
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"[[servers]] {name!r}: port не число") from exc
        if not 1 <= port <= 65535:
            raise ConfigError(f"[[servers]] {name!r}: порт вне диапазона 1..65535")
        known = {"name", "host", "port", "protocol", "detour"}
        servers.append(Server(
            name=name,
            host=host,
            port=port,
            protocol=protocol,
            detour=raw.get("detour") or "",
            params={k: v for k, v in raw.items() if k not in known},
        ))

    names = {s.name for s in servers}
    for s in servers:
        if s.detour and s.detour not in names:
            raise ConfigError(
                f"[[servers]] {s.name!r}: detour={s.detour!r} — такого звена нет. "
                "sing-box такую ошибку не ловит, она вылезет только при соединении"
            )
        if s.detour == s.name:
            raise ConfigError(f"[[servers]] {s.name!r}: detour указывает сам на себя")

    return Config(local=local, routing=routing, servers=tuple(servers), path=path)


def load(path: pathlib.Path | None = None) -> Config:
    """Прочитать настройки с диска. Понятная ошибка вместо трассировки."""
    path = pathlib.Path(path).expanduser() if path else default_path()
    if not path.exists():
        raise ConfigError(
            f"файла настроек нет: {path}\n"
            "скопируй config.example.toml туда и заполни свои значения"
        )
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: файл не разбирается как TOML — {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: не читается — {exc}") from exc
    return parse(data, path=path)
