"""Command line interface."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

from . import __version__, config, winnet

PRIVILEGED = {"install", "enable", "disable", "uninstall", "cleanup", "reconcile"}

COMPAT_NOTICE = [
    "Compatibility mode works around a VPN client that blocks port 53 outside its tunnel:",
    "  - local DNS is served on the tunnel address (port 53) instead of 127.0.0.1;",
    "  - domestic names are resolved over HTTPS (443) by AliDNS, outside the tunnel.",
    "That deliberately sidesteps the DNS-leak protection of your VPN client for domestic",
    "names (foreign names still resolve through the tunnel). Use `compat off` to revert.",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zoog-cn-bypass",
        description="China-direct split routing and DNS for ZoogVPN on Windows.",
    )
    parser.add_argument("--output-file", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.add_parser("install", help="install files and register the boot-time scheduled task")
    sub.add_parser("enable", help="enable the task and start it now")
    sub.add_parser("disable", help="stop the task and remove routes and DNS override")
    sub.add_parser("status", help="show state, routes and live routing checks (no admin needed)")
    sub.add_parser("uninstall", help="disable and remove the task and installed files")
    sub.add_parser("daemon", help="run the reconcile loop in the foreground (task entry point)")
    rec = sub.add_parser("reconcile", help="apply split routing once")
    rec.add_argument("--dry-run", action="store_true", help="only print what would be done")
    sub.add_parser("cleanup", help="rescue: remove every route and DNS rule added by this tool")
    compat = sub.add_parser(
        "compat",
        help="compatibility mode for VPN clients that block port 53 (DNS on tunnel IP + DoH)",
    )
    compat.add_argument("state", choices=["on", "off", "status"])
    sub.add_parser("update-data", help="refresh the China IP/domain lists (repository checkout only)")
    sub.add_parser("version", help="print the version")
    return parser


def _self_command() -> tuple[str, list[str]]:
    if config.frozen():
        return sys.executable, []
    return sys.executable, [str(config.package_dir())]


def _elevate(argv: list[str]) -> int:
    handle, output_path = tempfile.mkstemp(prefix="zoogcn-out-", suffix=".txt")
    os.close(handle)
    try:
        executable, prefix = _self_command()
        code = winnet.run_elevated(prefix + ["--output-file", output_path] + argv, executable)
        try:
            with open(output_path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            text = ""
        if text:
            print(text, end="" if text.endswith("\n") else "\n")
        if code == 1223:
            print("Administrator approval was declined.", file=sys.stderr)
        return code
    finally:
        try:
            os.unlink(output_path)
        except OSError:
            pass


def _print_lines(lines) -> None:
    for line in lines:
        print(line)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.output_file:
        redirected = open(args.output_file, "w", encoding="utf-8", buffering=1)
        sys.stdout = redirected
        sys.stderr = redirected

    command = args.command
    if command is None:
        parser.print_help()
        return 0

    needs_admin = (
        command in PRIVILEGED or (command == "compat" and args.state != "status")
    ) and not (command == "reconcile" and args.dry_run)
    if needs_admin and not winnet.is_admin():
        if args.output_file:
            print("Administrator rights are required.")
            return 77
        return _elevate(argv)

    try:
        if command == "version":
            print(__version__)
        elif command == "status":
            from .daemon import collect_status
            _print_lines(collect_status())
        elif command == "install":
            from . import installer
            _print_lines(installer.install())
            _print_lines(installer.enable())
        elif command == "enable":
            from . import installer
            _print_lines(installer.enable())
        elif command == "disable":
            from . import installer
            from .daemon import cleanup
            _print_lines(installer.disable(cleanup))
        elif command == "uninstall":
            from . import installer
            from .daemon import cleanup
            _print_lines(installer.uninstall(cleanup))
        elif command == "cleanup":
            from .daemon import cleanup
            _print_lines(cleanup())
        elif command == "compat":
            from . import installer
            if args.state == "status":
                print("Compatibility mode: " + ("ON" if config.Settings.load().compat_mode else "off"))
            else:
                if args.state == "on":
                    _print_lines(COMPAT_NOTICE)
                _print_lines(installer.set_compat_mode(args.state == "on"))
        elif command == "daemon":
            from .daemon import run_daemon
            return run_daemon(foreground_log=sys.stdout.isatty())
        elif command == "reconcile":
            return _reconcile(args.dry_run)
        elif command == "update-data":
            from . import updatedata
            _print_lines(updatedata.update())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


def _reconcile(dry_run: bool) -> int:
    from . import dnsproxy
    from .daemon import Reconciler, _setup_logging
    from .nrpt import Nrpt
    from .routes import StateStore

    settings = config.Settings.load()
    net = winnet.WinNet()
    if dry_run:
        reconciler = Reconciler(net, Nrpt(), lambda: True, StateStore(config.state_dir()), settings)
        _print_lines(reconciler.describe_plan())
        return 0

    _setup_logging(to_file=False)
    data = config.runtime_data_dir()
    target = (config.LOCAL_DNS, config.LOCAL_DNS_PORT)
    # A one-shot run has no resident proxy: the DNS override is only added when the
    # installed daemon's proxy already answers on 127.0.0.1:53.
    reconciler = Reconciler(
        net, Nrpt(),
        lambda: bool(dnsproxy.query_a("www.baidu.com", target)) and bool(dnsproxy.query_a("example.com", target)),
        StateStore(config.state_dir()), settings, data_dir=data,
    )
    ok = reconciler.reconcile()
    print("reconcile: ok" if ok else "reconcile: finished with errors (see `status`)")
    return 0 if ok else 2
