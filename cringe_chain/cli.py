"""Командная строка: тонкий слой над модулями, вся логика лежит в них."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

from . import audit, config as cfgmod, pacserver, probe, render, safety, system

TRACE_TARGET = "https://api.anthropic.com"


def _entry(cfg: cfgmod.Config) -> str:
    return f"http://127.0.0.1:{cfg.local.entry_port}"


def _load(args) -> cfgmod.Config:
    return cfgmod.load(pathlib.Path(args.config) if args.config else None)


def _preflight_or_stop(cfg, args) -> int | None:
    """Проверки до изменений. Возвращает код выхода, если идти дальше нельзя."""
    try:
        _, pac_port, _ = pacserver.endpoint(cfg)
    except cfgmod.ConfigError as exc:
        print(f"Настройки: {exc}", file=sys.stderr)
        return 2
    problems = safety.preflight(cfg, pacserver.LABEL, pac_port)
    for pr in problems:
        mark = "СТОП " if pr.fatal else "осторожно "
        print(f"  {mark}{pr.text}", file=sys.stderr)
        if pr.hint:
            print(f"        {pr.hint}", file=sys.stderr)
    if any(pr.fatal for pr in problems) and not getattr(args, "force", False):
        print("\nНичего не меняю. Исправь причину или повтори с --force, "
              "если понимаешь последствия.", file=sys.stderr)
        return 3
    return None


def cmd_apply(args) -> int:
    """Перегенерить конфиг sing-box и PAC из ОДНОГО списка доменов.

    Операция транзакционная: прежний конфиг сохраняется, новый проверяется
    сам по себе, и если служба после перезапуска не заняла порты — прежний
    файл возвращается на место и служба поднимается обратно. Без этого
    неудачный apply оставлял мёртвый прокси, на который смотрела вся система.
    """
    cfg = _load(args)
    sb = render.singbox_config(cfg)
    pac_text = render.pac(cfg)
    pac_path = pacserver.pac_file(cfg)
    text = json.dumps(sb, indent=2, ensure_ascii=False) + "\n"

    if args.dry_run:
        print(f"записал бы {cfg.local.singbox_config} ({len(text)} байт)")
        print(f"записал бы {pac_path} ({len(pac_text)} байт)")
        for d in (cfg.local.singbox_config.parent, pac_path.parent, cfg.local.singbox_log.parent):
            if not d.exists():
                print(f"создал бы каталог {d}")
        print(f"перезапустил бы sing-box через {cfg.local.brew}")
        return 0

    stop = _preflight_or_stop(cfg, args)
    if stop is not None:
        return stop

    for made in safety.ensure_dirs(cfg, pac_path):
        print(f"  создан каталог {made}")

    pac_path.write_text(pac_text)
    print(f"  PAC             -> {pac_path}")

    with safety.ConfigSwap(cfg.local.singbox_config, text) as swap:
        if swap.backup:
            print(f"  резерв прежнего -> {swap.backup.name}")
        ok, why = safety.config_is_valid(cfg.local.singbox_config)
        if not ok:
            print(f"  ! sing-box не принимает новый конфиг:\n    {why}", file=sys.stderr)
            print("  прежний конфиг возвращён, служба не трогалась", file=sys.stderr)
            return 1

        system.brew_service("restart", "sing-box", cfg.local.brew)
        live, why = safety.service_came_up(cfg)
        if not live:
            print(f"  ! служба не поднялась: {why}", file=sys.stderr)
            print("  возвращаю прежний конфиг и перезапускаю обратно...", file=sys.stderr)
            if swap.restore():
                system.brew_service("restart", "sing-box", cfg.local.brew)
                back, back_why = safety.service_came_up(cfg)
                print(f"  откат: {'служба поднялась на прежнем конфиге' if back else back_why}",
                      file=sys.stderr)
            else:
                print("  откат невозможен: прежнего конфига не было", file=sys.stderr)
            print("\n  последние строки журнала:", file=sys.stderr)
            print(safety.log_tail(cfg), file=sys.stderr)
            return 1
        swap.commit()

    print(f"  конфиг sing-box -> {cfg.local.singbox_config}")
    print(f"  в туннель: {len(cfg.routing.tunnel_domains)} доменов, "
          f"{len(cfg.routing.tunnel_cidrs)} подсетей")
    print(f"  служба: {why}")
    return 0


def cmd_rollback(args) -> int:
    """Вернуть прошлый конфиг из резерва и поднять службу на нём."""
    cfg = _load(args)
    backup = safety.latest_backup(cfg.local.singbox_config)
    if backup is None:
        print("Резервных копий конфига нет.", file=sys.stderr)
        return 1
    print(f"  возвращаю {backup.name}")
    if args.dry_run:
        print(f"  перезаписал бы {cfg.local.singbox_config} и перезапустил службу")
        return 0
    cfg.local.singbox_config.write_text(backup.read_text())
    system.brew_service("restart", "sing-box", cfg.local.brew)
    live, why = safety.service_came_up(cfg)
    print(f"  служба: {why}")
    return 0 if live else 1


def cmd_on(args) -> int:
    """Поднять службу и переключить систему.

    Порядок важен и выстрадан: система переключается на прокси ТОЛЬКО после
    того, как прокси ответил. Иначе HTTPS_PROXY указывает на мёртвый порт —
    а у переменной окружения, в отличие от PAC, нет запасного «иди напрямую»,
    и консольные программы остаются вообще без сети.
    """
    cfg = _load(args)
    print("Включаю:")
    if args.dry_run:
        print(f"  запустил бы sing-box через {cfg.local.brew}")
        for cmd in pacserver.install(cfg, dry_run=True):
            print("  " + cmd)
        for service in system.network_services():
            for cmd in system.set_pac(service, cfg.local.pac_url, dry_run=True):
                print("  " + cmd)
            for cmd in system.set_bypass(service, cfg.routing.bypass_domains, dry_run=True):
                print("  " + cmd)
        for var in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"):
            for cmd in system.setenv(var, "…", dry_run=True):
                print("  " + cmd)
        return 0

    stop = _preflight_or_stop(cfg, args)
    if stop is not None:
        return stop

    # 1. служба
    system.brew_service("start", "sing-box", cfg.local.brew)
    live, why = safety.service_came_up(cfg)
    if not live:
        print(f"  ! sing-box не поднялся: {why}", file=sys.stderr)
        print("  системные настройки НЕ трогал — ты остаёшься на прежней схеме.",
              file=sys.stderr)
        print("\n  последние строки журнала:", file=sys.stderr)
        print(safety.log_tail(cfg), file=sys.stderr)
        return 1
    print(f"  sing-box: {why}")

    # 2. раздатчик PAC, и убеждаемся, что он действительно отдаёт файл
    pacserver.install(cfg)
    state = pacserver.state(cfg)
    if "раздаёт" not in state:
        print(f"  ! раздатчик PAC не работает: {state}", file=sys.stderr)
        print("  снимаю его и не трогаю системные настройки.", file=sys.stderr)
        pacserver.uninstall()
        return 1
    print(f"  PAC: {state}")

    # 3. только теперь система
    for service in system.network_services():
        system.set_pac(service, cfg.local.pac_url)
        system.set_bypass(service, cfg.routing.bypass_domains)
        print(f"  прокси {service:<22} -> {system.proxy_state(service)}")

    for var, val in (("HTTPS_PROXY", _entry(cfg)),
                     ("HTTP_PROXY", _entry(cfg)),
                     ("NO_PROXY", ",".join(cfg.routing.no_proxy))):
        system.setenv(var, val)
    print("  переменные окружения прописаны (их подхватят программы, запущенные позже)")
    print()
    return cmd_status(args)


def _release_system(dry_run: bool = False) -> list[str]:
    """Отцепить систему от прокси. Порядок строгий и важный.

    Сперва переменные окружения, потом системный прокси, и только потом всё
    остальное. Наоборот нельзя: пока переменная указывает на порт, а службы
    за ним уже нет, у консольных программ нет сети вообще — у переменной, в
    отличие от PAC, нет запасного пути «остальное напрямую».

    Ничего не требует от настроек: эта функция должна работать и тогда, когда
    config.toml не читается. Это аварийная часть, ей нельзя зависеть от того,
    что могло сломаться.
    """
    done = []
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
                "https_proxy", "http_proxy", "all_proxy", "no_proxy"):
        system.unsetenv(var, dry_run=dry_run)
        done.append(f"снял {var}")
    for service in system.network_services():
        system.disable_proxy(service, dry_run=dry_run)
        done.append(f"прокси выключен у службы {service}")
    return done


def cmd_off(args) -> int:
    """Выключить прокси: система идёт напрямую.

    Это НЕ восстановление прежнего состояния — файл конфига остаётся как есть.
    Если сломан он, нужен rescue или rollback.
    """
    print("Выключаю:")
    for line in _release_system(dry_run=args.dry_run):
        print("  " + line)
    pacserver.uninstall(dry_run=args.dry_run)
    print("  раздатчик PAC снят")
    try:
        cfg = _load(args)
        system.brew_service("stop", "sing-box", cfg.local.brew, dry_run=args.dry_run)
        print("  служба остановлена")
        print(f"\nФайл {cfg.local.singbox_config} НЕ тронут. Если дело в нём — "
              "верни прежний командой rollback, а полное восстановление — rescue.")
    except cfgmod.ConfigError as exc:
        print(f"  настройки не прочитались ({exc}); служба не остановлена",
              file=sys.stderr)
        print("  но система от прокси отцеплена — сеть должна работать напрямую")
    print("\nПрограммы, запущенные раньше, могли запомнить прокси — их надо перезапустить.")
    return 0


def cmd_rescue(args) -> int:
    """Аварийное восстановление: вернуть сеть, чего бы это ни стоило.

    Задумано как кнопка для положения «всё сломалось и я не понимаю что».
    Поэтому: сначала отцепляем систему от прокси (сеть возвращается сразу же,
    напрямую), и только потом разбираемся с конфигом. И поэтому же команда
    не падает, если настройки не читаются, — она обязана работать в худшем
    случае, а не в лучшем.
    """
    print("АВАРИЙНОЕ ВОССТАНОВЛЕНИЕ")
    print("\n1. Отцепляю систему от прокси — сеть пойдёт напрямую:")
    for line in _release_system(dry_run=args.dry_run):
        print("  " + line)
    pacserver.uninstall(dry_run=args.dry_run)
    print("  раздатчик PAC снят")

    if args.dry_run:
        print("\n2. (сухой прогон) вернул бы прежний конфиг и поднял службу")
        return 0

    print("\n   Сеть сейчас должна работать напрямую, без туннеля.")

    try:
        cfg = _load(args)
    except cfgmod.ConfigError as exc:
        print(f"\n2. Настройки не читаются: {exc}", file=sys.stderr)
        print("   Дальше автоматически сделать нечего, но главное уже сделано.",
              file=sys.stderr)
        return 1

    system.brew_service("stop", "sing-box", cfg.local.brew)
    print("\n2. Ищу конфиг, на котором служба действительно поднимается:")
    backups = sorted(cfg.local.singbox_config.parent.glob(
        cfg.local.singbox_config.name + ".backup-*"), reverse=True)
    candidates = [cfg.local.singbox_config] + backups
    for cand in candidates:
        if not cand.exists():
            continue
        if cand != cfg.local.singbox_config:
            cfg.local.singbox_config.write_text(cand.read_text())
        ok, why = safety.config_is_valid(cfg.local.singbox_config)
        if not ok:
            print(f"   {cand.name}: отвергнут проверкой — {why.splitlines()[0][:70]}")
            continue
        safety.ensure_dirs(cfg, pacserver.pac_file(cfg))
        system.brew_service("restart", "sing-box", cfg.local.brew)
        live, why = safety.service_came_up(cfg, seconds=20)
        print(f"   {cand.name}: {'ПОДНЯЛАСЬ' if live else why}")
        if live:
            print(f"\n3. Служба работает на {cand.name}.")
            print("   Системный прокси остался выключенным — включить: cringe on")
            return 0
    print("\n3. Ни один конфиг не поднимается. Последние строки журнала:", file=sys.stderr)
    print(safety.log_tail(cfg), file=sys.stderr)
    print("   Сеть работает напрямую; туннель нужно чинить руками.", file=sys.stderr)
    return 1


def cmd_status(args) -> int:
    cfg = _load(args)
    entry = _entry(cfg)
    final = cfg.final_server
    tr = probe.trace(TRACE_TARGET, proxy=entry)
    data = {
        "singbox": system.service_state("sing-box", cfg.local.brew),
        "pac": pacserver.state(cfg),
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
    print(f"  раздатчик PAC       : {data['pac']}")
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
    """Проверки снизу вверх: сперва то, что ломает тихо, потом сеть."""
    cfg = _load(args)
    entry = _entry(cfg)
    rc = 0

    print("Предохранители:")
    try:
        _, pac_port, _ = pacserver.endpoint(cfg)
    except cfgmod.ConfigError as exc:
        print(f"  СТОП {exc}")
        return 2
    problems = safety.preflight(cfg, pacserver.LABEL, pac_port)
    if not problems:
        print("  всё чисто")
    for pr in problems:
        print(f"  {'СТОП ' if pr.fatal else 'осторожно '}{pr.text}")
        if pr.hint:
            print(f"        {pr.hint}")
        rc = max(rc, 3 if pr.fatal else 0)

    print("Каталоги, куда пакет пишет:")
    for d in (cfg.local.singbox_config.parent, pacserver.pac_file(cfg).parent,
              cfg.local.singbox_log.parent):
        print(f"  {'есть    ' if d.exists() else 'НЕТ     '}{d}")

    print("Звенья цепочки:")
    for server in render.chain_order(cfg):
        check = probe.port_open(server.host, server.port)
        detour = f" (через {server.detour})" if server.detour else ""
        print(f"  {server.name:<16} {server.host}:{server.port:<6} "
              f"{'открыт' if check.open else 'НЕ ДОХОДИТ'}{detour}")

    print("Локальные порты:")
    for port in (cfg.local.entry_port, cfg.local.socks_port):
        print(f"  127.0.0.1:{port:<6} {'слушает' if system.wait_for_port(port, 3) else 'молчит'}")

    print("Через прокси:")
    tr = probe.trace(TRACE_TARGET, proxy=entry)
    print(f"  нас видят как       -> ip={tr.ip} loc={tr.loc}")
    return rc


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

    def add(name, func, help_text, *, dry=False, as_json=False, force=False):
        sp = sub.add_parser(name, help=help_text)
        sp.set_defaults(func=func, dry_run=False, json=False, force=False)
        if dry:
            sp.add_argument("--dry-run", action="store_true",
                            help="ничего не делать, напечатать команды")
        if as_json:
            sp.add_argument("--json", action="store_true", help="машиночитаемый вывод")
        if force:
            sp.add_argument("--force", action="store_true",
                            help="выполнить, несмотря на сработавшие предохранители")
        return sp

    add("apply", cmd_apply, "перегенерить конфиг sing-box и PAC из настроек",
        dry=True, force=True)
    add("rollback", cmd_rollback, "вернуть прошлый конфиг из резерва", dry=True)
    add("on", cmd_on, "поднять службу и включить системный прокси", dry=True, force=True)
    add("off", cmd_off, "выключить прокси и остановить службу", dry=True)
    add("rescue", cmd_rescue,
        "аварийно вернуть сеть: отцепить систему и поднять службу на рабочем конфиге",
        dry=True)
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
