"""Сборка выдачи из настроек: конфиг sing-box, PAC-файл и ссылки для клиентов.

Функции здесь чистые: ничего не читают с диска, ничего не пишут и не лезут в сеть.
Всё приходит из Config, поэтому результат воспроизводим и проверяем тестами,
а записью на диск занимается вызывающий код.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote, urlencode

from .config import SHADOWSOCKS, VLESS_REALITY, Config, ConfigError, Server

# Встроенный выход sing-box «мимо прокси». Имя занято, сервер так назвать нельзя.
DIRECT = "direct"

FINGERPRINT = "chrome"


def _unsupported(server: Server) -> ConfigError:
    return ConfigError(
        f"[[servers]] {server.name!r}: протокол {server.protocol!r} не поддерживается "
        f"(есть {SHADOWSOCKS} и {VLESS_REALITY})"
    )


def _param(server: Server, key: str) -> str:
    """Обязательное поле из server.params.

    Пустое значение подставлять нельзя: sing-box проглотит конфиг с пустым
    паролем или pbk и упадёт уже на живом соединении, без внятного текста.
    """
    value = server.params.get(key)
    if value is None or value == "":
        raise ConfigError(
            f"[[servers]] {server.name!r}: не задано поле {key!r}, "
            f"а для протокола {server.protocol} оно обязательно"
        )
    return str(value)


def _detour_of(cfg: Config, server: Server) -> Server:
    try:
        return cfg.server(server.detour)
    except ConfigError as exc:
        raise ConfigError(
            f"[[servers]] {server.name!r}: detour ведёт в никуда — {exc}"
        ) from exc


def _check_no_ring(cfg: Config) -> None:
    """Кольцо detour (a -> b -> a) — своя проверка, чужой нет.

    `sing-box check` принимает и кольцо, и ссылку в никуда: ошибка вылезает
    только при соединении, и выглядит она как «интернета нет».
    """
    for start in cfg.servers:
        seen = [start.name]
        node = start
        while node.detour:
            if node.detour in seen:
                ring = seen[seen.index(node.detour):] + [node.detour]
                raise ConfigError(
                    "цепочка замкнулась в кольцо: " + " -> ".join(ring)
                    + "; у каждого звена в detour должно стоять имя ПРЕДЫДУЩЕГО, "
                    "а у первого — пусто"
                )
            node = _detour_of(cfg, node)
            seen.append(node.name)


def chain_order(cfg: Config) -> list[Server]:
    """Звенья от первого (ближнего к нам) к последнему (его адрес увидит цель).

    Порядок восстанавливается по detour: идём от хвоста к голове и переворачиваем.
    """
    if not cfg.servers:
        raise ConfigError("в настройках нет ни одного сервера — цепочку не из чего строить")

    _check_no_ring(cfg)

    chain: list[Server] = []
    node = cfg.final_server
    while True:
        chain.append(node)
        if not node.detour:
            break
        node = _detour_of(cfg, node)
    chain.reverse()

    # Звено вне цепочки попало бы в конфиг недостижимым outbound-ом.
    in_chain = {s.name for s in chain}
    stray = [s.name for s in cfg.servers if s.name not in in_chain]
    if stray:
        raise ConfigError(
            "эти звенья не входят в цепочку: " + ", ".join(stray)
            + "; проверь поля detour"
        )
    return chain


def _outbound(server: Server) -> dict:
    """Один outbound sing-box. Значения — только из настроек, умолчаний нет."""
    if server.is_shadowsocks:
        out: dict = {
            "type": SHADOWSOCKS,
            "tag": server.name,
            "server": server.host,
            "server_port": server.port,
            "method": _param(server, "method"),
            "password": _param(server, "password"),
        }
    elif server.is_reality:
        out = {
            "type": "vless",
            "tag": server.name,
            "server": server.host,
            "server_port": server.port,
            "uuid": _param(server, "uuid"),
            "flow": _param(server, "flow"),
            "tls": {
                "enabled": True,
                "server_name": _param(server, "server_name"),
                "utls": {"enabled": True, "fingerprint": FINGERPRINT},
                "reality": {
                    "enabled": True,
                    "public_key": _param(server, "public_key"),
                    "short_id": _param(server, "short_id"),
                },
            },
        }
    else:
        raise _unsupported(server)

    # detour = имя предыдущего звена: до этого сервера идём через него.
    if server.detour:
        out["detour"] = server.detour
    return out


def singbox_config(cfg: Config) -> dict:
    """Конфиг sing-box целиком, готовый к json.dump."""
    chain = chain_order(cfg)
    for server in chain:
        if server.name == DIRECT:
            raise ConfigError(
                f"[[servers]] {DIRECT!r}: это имя занято встроенным выходом sing-box, "
                "назови звено иначе"
            )

    last = chain[-1].name
    outbounds = [_outbound(s) for s in chain]
    outbounds.append({"type": DIRECT, "tag": DIRECT})

    # В туннель уходит только перечисленное; всё остальное — мимо прокси ("final").
    rules: list[dict] = []
    if cfg.routing.tunnel_domains:
        rules.append({"domain_suffix": list(cfg.routing.tunnel_domains), "outbound": last})
    if cfg.routing.tunnel_cidrs:
        rules.append({"ip_cidr": list(cfg.routing.tunnel_cidrs), "outbound": last})

    return {
        "log": {
            "level": cfg.local.log_level,
            "timestamp": True,
            "output": str(cfg.local.singbox_log),
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "entry-in",
                "listen": "127.0.0.1",
                "listen_port": cfg.local.entry_port,
            },
            {
                "type": "mixed",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": cfg.local.socks_port,
            },
        ],
        "outbounds": outbounds,
        "route": {"rules": rules, "final": DIRECT},
    }


def pac(cfg: Config) -> str:
    """Текст PAC-файла для системного прокси.

    Ключевая вещь во всём пакете: список доменов берётся из того же
    routing.tunnel_domains, что и правило route в singbox_config. Пока обе выдачи
    собираются из одного поля, разойтись им негде — а расходились они именно так:
    домен добавляли в один файл и забывали во втором, после чего «в браузере
    работает, в терминале нет» (или наоборот).
    """
    proxy = f"SOCKS5 127.0.0.1:{cfg.local.socks_port}; PROXY 127.0.0.1:{cfg.local.entry_port}"
    # json.dumps, а не кавычки руками: домен с нестандартным символом не сломает JS.
    domains = ",\n".join("    " + json.dumps(d) for d in cfg.routing.tunnel_domains)
    return f"""\
// Собрано cringe-chain. Руками не править: файл переписывается целиком,
// домены живут в настройках (routing.tunnel_domains) вместе с правилами sing-box.
var TUNNEL = [
{domains}
];
var PROXY = {json.dumps(proxy)};

function FindProxyForURL(url, host) {{
    host = host.toLowerCase();
    for (var i = 0; i < TUNNEL.length; i++) {{
        // Точное равенство ловит сам домен, dnsDomainIs с ведущей точкой —
        // только поддомены. Точка обязательна: без неё под правило попал бы
        // любой чужой домен, чьё имя просто кончается на наше.
        if (host === TUNNEL[i] || dnsDomainIs(host, "." + TUNNEL[i])) {{
            return PROXY;
        }}
    }}
    return "DIRECT";
}}
"""


def share_link(server: Server) -> str:
    """Ссылка на одно звено для импорта в сторонний клиент (и для QR-кода)."""
    tag = quote(server.name, safe="")

    if server.is_shadowsocks:
        userinfo = base64.urlsafe_b64encode(
            f"{_param(server, 'method')}:{_param(server, 'password')}".encode()
        ).decode()
        # Паддинг '=' в ss:// не кладут: часть клиентов на нём спотыкается.
        return f"ss://{userinfo.rstrip('=')}@{server.host}:{server.port}#{tag}"

    if server.is_reality:
        query = urlencode(
            {
                "encryption": "none",
                "security": "reality",
                "type": "tcp",
                "sni": _param(server, "server_name"),
                "fp": FINGERPRINT,
                "pbk": _param(server, "public_key"),
                "sid": _param(server, "short_id"),
                "flow": _param(server, "flow"),
            }
        )
        uuid = _param(server, "uuid")
        return f"vless://{uuid}@{server.host}:{server.port}?{query}#{tag}"

    raise _unsupported(server)
