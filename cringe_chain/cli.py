"""Командная строка: тонкий слой над модулями, вся логика лежит в них."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

from . import audit, config as cfgmod, probe, render, system

TRACE_TARGET = "https://api.anthropic.com"


def _entry(cfg: cfgmod.Config) -> str:
    return f"http://127.0.0.1:{cfg.local.entry_port}"


def _load(args) -> cfgmod.Config:
    return cfgmod.load(pathlib.Path(args.config) if args.config else None)


def cmd_apply(args) -> int:
    """Перегенерить конфиг sing-box и PAC из ОДНОГО списка доменов.

    Смысл команды в том, что после неё они не могут разойтись: оба файла
    порождены одним полем настроек.
    """
    cfg = _load(args)
    sb = render.singbox_config(cfg)
    pac_text = render.pac(cfg)
    pac_path = cfg.local.pac_dir / "proxy.pac"

    if args.dry_run:
        print(f"записал бы {cfg.local.singbox_config} ({len(json.dumps(sb))} байт)")
        print(f"записал бы {pac_path} ({len(pac_text)} байт)")
        print(f"перезапустил бы sing-box через {cfg.local.brew}")
        return 0

    cfg.local.singbox_config.parent.mkdir(parents=True, exist_ok=True)
    cfg.local.singbox_config.write_text(json.dumps(sb, indent=2, ensure_ascii=False) + "\n")
    pac_path.parent.mkdir(parents=True, exist_ok=True)
    pac_path.write_text(pac_text)
    print(f"  конфиг sing-box -> {cfg.local.singbox_config}")
    print(f"  PAC             -> {pac_path}")

    doms = len(cfg.routing.tunnel_domains)
    print(f"  в туннель: {doms} доменов, {len(cfg.routing.tunnel_cidrs)} подсетей")
    system.brew_service("restart", "sing-box", cfg.local.brew)
    if system.wait_for_port(cfg.local.entry_port, 20):
        print("  sing-box перезапущен и слушает")
    else:
        print("  ! sing-box не занял порт, смотри его журнал", file=sys.stderr)
        return 1
    return 0


def cmd_on(args) -> int:
    cfg = _load(args)
    print("Включаю:")
    system.brew_service("start", "sing-box", cfg.local.brew, dry_run=args.dry_run)
    if not args.dry_run and not system.wait_for_port(cfg.local.entry_port, 20):
        print("  ! sing-box не поднялся за 20 секунд", file=sys.stderr)
        return 1

    for service in system.network_services():
        for cmd in system.set_pac(service, cfg.local.pac_url, dry_run=args.dry_run):
            if args.dry_run:
                print("  " + cmd)
        for cmd in system.set_bypass(service, cfg.routing.bypass_domains, dry_run=args.dry_run):
            if args.dry_run:
                print("  " + cmd)
        if not args.dry_run:
            print(f"  прокси {service:<20} -> {system.proxy_state(service)}")

    for var, val in (("HTTPS_PROXY", _entry(cfg)),
                     ("HTTP_PROXY", _entry(cfg)),
                     ("NO_PROXY", ",".join(cfg.routing.no_proxy))):
        for cmd in system.setenv(var, val, dry_run=args.dry_run):
            if args.dry_run:
                print("  " + cmd)
    if not args.dry_run:
        print("  переменные окружения прописаны (их подхватят программы, запущенные позже)")
        print()
        return cmd_status(args)
    return 0


def cmd_off(args) -> int:
    cfg = _load(args)
    print("Выключаю:")
    for service in system.network_services():
        for cmd in system.disable_proxy(service, dry_run=args.dry_run):
            if args.dry_run:
                print("  " + cmd)
        if not args.dry_run:
            print(f"  прокси {service:<20} -> {system.proxy_state(service)}")
    system.brew_service("stop", "sing-box", cfg.local.brew, dry_run=args.dry_run)
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):
        for cmd in system.unsetenv(var, dry_run=args.dry_run):
            if args.dry_run:
                print("  " + cmd)
    if not args.dry_run:
        print("  переменные окружения сняты")
        print("\nПрограммы, запущенные раньше, могли запомнить прокси — их надо перезапустить.")
    return 0


def cmd_status(args) -> int:
    cfg = _load(args)
    entry = _entry(cfg)
    final = cfg.final_server
    tr = probe.trace(TRACE_TARGET, proxy=entry)
    data = {
        "singbox": system.service_state("sing-box", cfg.local.brew),
        "services": {s: system.proxy_state(s) for s in system.network_services()},
        "exit_ip_via_tunnel": tr.ip,
        "exit_loc": tr.loc,
        "exit_ip_direct": probe.exit_ip(),
        "expected_host": final.host,
        "ok": bool(tr.ip) and tr.ip == final.host,
    }
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0 if data["ok"] else 1

    print(f"  sing-box            : {data['singbox']}")
    for name, state in data["services"].items():
        print(f"  прокси {name:<20} {state}")
    print(f"  цель видит нас как  : ip={tr.ip} loc={tr.loc} (узел {tr.colo})")
    print(f"  ждём адрес звена    : {final.host}  ({final.name})")
    print(f"  обычный трафик      : {data['exit_ip_direct']}")
    print("  ИТОГ:", "всё на месте" if data["ok"] else "что-то не сходится")
    return 0 if data["ok"] else 1


def cmd_leaks(args) -> int:
    """Что ушло мимо туннеля, хотя должно было идти через него."""
    cfg = _load(args)
    sb = json.loads(cfg.local.singbox_config.read_text())
    mtime = dt.datetime.fromtimestamp(cfg.local.singbox_config.stat().st_mtime)
    report = audit.audit_file(sb, cfg.local.singbox_log, mtime)

    if args.json:
        print(json.dumps({
            "total": report.total, "direct": report.direct,
            "stale": [vars(l) for l in report.stale],
            "missing": [vars(l) for l in report.missing],
        }, ensure_ascii=False, indent=2))
        return 1 if (report.stale or report.missing) else 0

    print(f"Журнал {cfg.local.singbox_log}: соединений {report.total}, мимо туннеля {report.direct}")
    if report.first_ts:
        print(f"  период: {report.first_ts} … {report.last_ts}")
    print("\n1) Правило есть, а трафик ушёл мимо — sing-box не перечитал конфиг:")
    if report.stale:
        for leak in sorted(report.stale, key=lambda l: -l.count):
            print(f"   {leak.host:<44} {leak.count:>6} раз, последний {leak.last}")
        print(f"   Лечение: {cfg.local.brew} services restart sing-box")
    else:
        print("   нет таких")
        if report.explained:
            names = ", ".join(l.host for l in report.explained[:5])
            print(f"   (до правки конфига так ушли: {names} — правило добавлено позже)")
    print("2) Похож на наш, но правила нет — это и есть утечка:")
    if report.missing:
        for leak in sorted(report.missing, key=lambda l: -l.count):
            print(f"   {leak.host:<44} {leak.count:>6} раз, последний {leak.last}")
        print("   Лечение: добавить домен в tunnel_domains настроек и выполнить cringe apply")
    else:
        print("   нет таких")

    print("\nСлепая зона: сюда попадает только трафик, дошедший до sing-box.")
    print("Программа со старым PAC пройдёт мимо совсем, и отчёт будет чистым.")
    return 1 if (report.stale or report.missing) else 0


def cmd_doctor(args) -> int:
    """Проверки снизу вверх: бессмысленно разбирать правила, пока не доходит TCP."""
    cfg = _load(args)
    entry = _entry(cfg)
    print("Звенья цепочки:")
    for server in render.chain_order(cfg):
        check = probe.port_open(server.host, server.port)
        mark = "открыт" if check.open else "НЕ ДОХОДИТ"
        detour = f" (через {server.detour})" if server.detour else ""
        print(f"  {server.name:<16} {server.host}:{server.port:<6} {mark}{detour}")
    print("Локальные порты:")
    for port in (cfg.local.entry_port, cfg.local.socks_port):
        print(f"  127.0.0.1:{port:<6} {'слушает' if system.wait_for_port(port, 3) else 'молчит'}")
    print("Через прокси:")
    print(f"  цель                -> {probe.http_code(TRACE_TARGET + '/v1/messages', proxy=entry)}")
    tr = probe.trace(TRACE_TARGET, proxy=entry)
    print(f"  нас видят как       -> ip={tr.ip} loc={tr.loc}")
    return 0


def cmd_link(args) -> int:
    """Ссылка для клиента: её можно вставить в телефонное приложение."""
    cfg = _load(args)
    server = cfg.server(args.server)
    link = render.share_link(server)
    out = pathlib.Path(args.out).expanduser() if args.out else None
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(link + "\n")
        out.chmod(0o600)
        print(f"ссылка записана в {out} (права 600 — внутри персональный ключ)")
    else:
        print(link)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cringe",
        description="Селективный прокси через цепочку своих серверов. Настройки в TOML.",
    )
    p.add_argument("--config", help="путь к config.toml (по умолчанию ~/.config/cringe-chain/config.toml)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, func, help_text, *, dry=False, as_json=False):
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func, dry_run=False, json=False)
        if dry:
            sp.add_argument("--dry-run", action="store_true",
                            help="ничего не делать, напечатать команды")
        if as_json:
            sp.add_argument("--json", action="store_true", help="машиночитаемый вывод")
        return sp

    add("apply", cmd_apply, "перегенерить конфиг sing-box и PAC из настроек", dry=True)
    add("on", cmd_on, "поднять службу и включить системный прокси", dry=True)
    add("off", cmd_off, "выключить прокси и остановить службу", dry=True)
    add("status", cmd_status, "что включено и куда реально идёт трафик", as_json=True)
    add("leaks", cmd_leaks, "что ушло мимо туннеля", as_json=True)
    add("doctor", cmd_doctor, "проверить каждое звено по очереди")
    link = add("link", cmd_link, "ссылка на подключение для клиента")
    link.add_argument("server", help="имя звена из настроек")
    link.add_argument("--out", help="записать в файл вместо печати")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except cfgmod.ConfigError as exc:
        print(f"Настройки: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
