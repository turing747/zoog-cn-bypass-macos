"""Installation: files in %ProgramData%, ACL hardening and the scheduled task."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from . import config, winnet

# Locale-independent well-known SIDs.
_SID_SYSTEM = "*S-1-5-18"
_SID_ADMINS = "*S-1-5-32-544"
_SID_USERS = "*S-1-5-32-545"


def _run(args: list[str], check: bool = False) -> subprocess.CompletedProcess:
    result = winnet.run_hidden(args, timeout=120)
    if check and result.returncode != 0:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {(result.stderr or result.stdout).strip()}")
    return result


def task_exists() -> bool:
    return _run(["schtasks.exe", "/Query", "/TN", config.TASK_NAME]).returncode == 0


def _harden(directory: Path) -> None:
    """Only SYSTEM/Administrators may write; Users may read (status needs the state)."""
    _run(
        [
            "icacls.exe", str(directory), "/inheritance:r",
            "/grant:r", f"{_SID_SYSTEM}:(OI)(CI)F",
            "/grant:r", f"{_SID_ADMINS}:(OI)(CI)F",
            "/grant:r", f"{_SID_USERS}:(OI)(CI)RX",
        ],
        check=True,
    )


def _task_command() -> tuple[str, str, str]:
    """(command, arguments, working directory) executed by the scheduled task."""
    app = config.app_dir()
    if config.frozen():
        exe = app / "zoog-cn-bypass.exe"
        return str(exe), "daemon", str(app)
    return sys.executable, f'-I -E -s "{app / "run_daemon.py"}" daemon', str(app)


def _task_xml() -> str:
    command, arguments, workdir = _task_command()
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>ZoogCNBypass: China-direct split routing and DNS for ZoogVPN</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(command)}</Command>
      <Arguments>{escape(arguments)}</Arguments>
      <WorkingDirectory>{escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _warn_if_user_writable_python(messages: list[str]) -> None:
    if config.frozen():
        return
    exe = Path(sys.executable).resolve()
    for variable in ("LOCALAPPDATA", "APPDATA", "USERPROFILE"):
        base = os.environ.get(variable)
        if base and str(exe).lower().startswith(base.lower()):
            messages.append(
                f"WARNING: {exe} lives in a user-writable folder; the SYSTEM task would run it. "
                "Prefer a machine-wide Python (C:\\Python3xx or C:\\Program Files)."
            )
            return


def install() -> list[str]:
    messages: list[str] = []
    source_data = config.source_data_dir()
    if source_data is None:
        raise FileNotFoundError("data directory not found; run install from the repository")

    if task_exists():
        _run(["schtasks.exe", "/End", "/TN", config.TASK_NAME])

    root = config.install_dir()
    root.mkdir(parents=True, exist_ok=True)
    _harden(root)

    app = config.app_dir()
    if app.exists():
        shutil.rmtree(app, ignore_errors=True)
    app.mkdir(parents=True)
    if config.frozen():
        shutil.copy2(sys.executable, app / "zoog-cn-bypass.exe")
    else:
        shutil.copytree(
            config.package_dir(), app / "zoog_cn_bypass",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "data"),
        )
        (app / "run_daemon.py").write_text(
            "import os, sys\n"
            "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
            "from zoog_cn_bypass.cli import main\n"
            "sys.exit(main())\n",
            encoding="utf-8",
        )

    data = config.installed_data_dir()
    data.mkdir(exist_ok=True)
    for name in config.DATA_FILES:
        shutil.copy2(source_data / name, data / name)
    config.state_dir().mkdir(exist_ok=True)
    config.log_dir().mkdir(exist_ok=True)
    cfg = root / "config.json"
    if not cfg.exists():
        cfg.write_text(config.DEFAULT_CONFIG_JSON, encoding="utf-8")

    _warn_if_user_writable_python(messages)

    xml_path = Path(tempfile.mkdtemp(prefix="zoogcn-")) / "task.xml"
    xml_path.write_text(_task_xml(), encoding="utf-16")
    try:
        _run(["schtasks.exe", "/Create", "/TN", config.TASK_NAME, "/XML", str(xml_path), "/F"], check=True)
    finally:
        shutil.rmtree(xml_path.parent, ignore_errors=True)
    messages.append(f"Installed to {root}")
    messages.append(f"Scheduled task '{config.TASK_NAME}' registered (runs at boot as SYSTEM)")
    return messages


def restart() -> list[str]:
    """Restart the daemon so new configuration is picked up."""
    if not task_exists():
        return ["Not installed; the setting applies after `install`."]
    _run(["schtasks.exe", "/End", "/TN", config.TASK_NAME])
    _run(["schtasks.exe", "/Change", "/TN", config.TASK_NAME, "/ENABLE"])
    _run(["schtasks.exe", "/Run", "/TN", config.TASK_NAME], check=True)
    return ["Daemon restarted."]


def set_compat_mode(enabled: bool) -> list[str]:
    """Persist ``compat_mode`` in config.json (installed copy) and restart the daemon."""
    import json

    path = config.install_dir() / "config.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = json.loads(config.DEFAULT_CONFIG_JSON)
    data["compat_mode"] = enabled
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return [f"Compatibility mode {'ON' if enabled else 'off'}."] + restart()


def enable() -> list[str]:
    if not task_exists():
        raise RuntimeError("not installed; run `install` first")
    _run(["schtasks.exe", "/Change", "/TN", config.TASK_NAME, "/ENABLE"], check=True)
    _run(["schtasks.exe", "/Run", "/TN", config.TASK_NAME], check=True)
    return ["ZoogCNBypass enabled. It activates while ZoogVPN is connected (check: status)."]


def disable(cleanup_fn) -> list[str]:
    messages: list[str] = []
    if task_exists():
        _run(["schtasks.exe", "/End", "/TN", config.TASK_NAME])
        _run(["schtasks.exe", "/Change", "/TN", config.TASK_NAME, "/DISABLE"])
    messages.extend(cleanup_fn())
    messages.append("ZoogCNBypass disabled. ZoogVPN itself was not disconnected.")
    return messages


def uninstall(cleanup_fn) -> list[str]:
    messages = disable(cleanup_fn)
    if task_exists():
        _run(["schtasks.exe", "/Delete", "/TN", config.TASK_NAME, "/F"])
    root = config.install_dir()
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            messages.append(f"Some files in {root} could not be removed; delete the folder manually")
    messages.append("ZoogCNBypass uninstalled.")
    return messages
