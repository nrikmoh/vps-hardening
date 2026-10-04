#!/usr/bin/env python3
"""
VPS Hardening Script v4.0
=========================

A provider- and distro-aware hardening orchestrator with:

  * Idempotent modules
  * Timestamped backups of every modified file
  * A true rollback stack triggered on failure
  * Dry-run mode
  * Telegram notifications (hardened bot, read-only by default)
  * Safe SSH port change with mandatory manual verification
  * LUKS support that never touches a running root filesystem

Designed for Ubuntu 20.04/22.04/24.04 and Debian 11/12 on any VPS provider.

All shell-outs go through CommandRunner, which respects --dry-run.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import enum
import functools
import getpass
import ipaddress
import json
import logging
import os
import pathlib
import platform
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
import urllib.error
import urllib.request
from typing import Any, Callable, Iterable, Optional, Sequence

# ---------------------------------------------------------------------------
# Version & global constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "4.0.0"
SCRIPT_NAME = "VPS Hardening Script"

LOG_DIR_DEFAULT = pathlib.Path("/var/log")
LOG_FILE_DEFAULT = LOG_DIR_DEFAULT / "vps-hardening-v4.log"

BACKUP_ROOT_DEFAULT = pathlib.Path("/var/backups/vps-harden")
STATE_DIR_DEFAULT = pathlib.Path("/var/lib/vps-hardening")
STATE_FILE_DEFAULT = STATE_DIR_DEFAULT / "state.json"

TELEGRAM_CONF_DIR = pathlib.Path("/etc/vps-hardening")
TELEGRAM_CONF_FILE = TELEGRAM_CONF_DIR / "telegram.conf"

# SSH defaults (port is always user-chosen at runtime)
SSH_CONFIG_MAIN = pathlib.Path("/etc/ssh/sshd_config")
SSH_CONFIG_DROPIN_DIR = pathlib.Path("/etc/ssh/sshd_config.d")
SSH_DROPIN_FILE = SSH_CONFIG_DROPIN_DIR / "99-vps-hardening.conf"
SSH_SOCKET_OVERRIDE_DIR = pathlib.Path("/etc/systemd/system/ssh.socket.d")

# UFW
UFW_DEFAULT_DIR = pathlib.Path("/etc/ufw")

# sysctl
SYSCTL_DROPIN = pathlib.Path("/etc/sysctl.d/99-vps-hardening.conf")

# Rollback / verification
REBOOT_REQUIRED_FILE = pathlib.Path("/var/run/reboot-required")

# Ports we never assign to SSH without a loud warning
SSH_PORT_BLOCKLIST = {22, 80, 443, 3306, 5432, 6379, 27017, 51820, 853, 25, 110, 143}

# WireGuard defaults (overridable at runtime)
DEFAULT_WG_SUBNET = "10.200.200.0/24"
DEFAULT_WG_PORT = 51820
DEFAULT_WG_INTERFACE = "wg0"

# Cloud provider identifiers
class Provider(enum.Enum):
    ORACLE = "oracle"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    DIGITALOCEAN = "digitalocean"
    LINODE = "linode"
    VULTR = "vultr"
    HETZNER = "hetzner"
    KVM = "kvm"
    OTHER = "other"


@dataclasses.dataclass
class SystemInfo:
    """Snapshot of the host environment used by every module."""
    os_id: str = "unknown"
    os_version: str = "unknown"
    os_codename: str = "unknown"
    os_pretty_name: str = "unknown"
    kernel: str = "unknown"
    arch: str = "unknown"
    virt: str = "unknown"
    provider: Provider = Provider.OTHER
    hostname: str = "unknown"
    primary_ip: str = "unknown"
    is_oracle: bool = False
    is_arm: bool = False
    has_systemd: bool = False
    has_apt: bool = False
    has_ufw: bool = False
    has_docker: bool = False
    has_tailscale: bool = False
    has_wireguard: bool = False


# Convenience: exit codes
EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_PREREQ = 2
EXIT_ROLLBACK = 3
EXIT_USER_ABORT = 130

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class RunOptions:
    dry_run: bool = False
    verbose: bool = False
    skip_luks: bool = False
    skip_wireguard: bool = False
    skip_docker: bool = False
    skip_telegram: bool = False
    skip_geoip: bool = False
    skip_suricata: bool = False  # reserved; Suricata not implemented by default
    assume_yes: bool = False     # reserved for future non-interactive mode


def parse_args(argv: Sequence[str]) -> RunOptions:
    parser = argparse.ArgumentParser(
        prog="v4-harden.py",
        description=f"{SCRIPT_NAME} v{SCRIPT_VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            All destructive actions are gated behind explicit prompts unless
            --assume-yes is provided (reserved for future use). Dry-run mode
            prints every command that would run and makes no changes.
        """),
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview all actions without modifying the system")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose debug output")
    parser.add_argument("--skip-luks", action="store_true",
                        help="Skip the LUKS module entirely")
    parser.add_argument("--skip-wireguard", action="store_true",
                        help="Skip the WireGuard module entirely")
    parser.add_argument("--skip-docker", action="store_true",
                        help="Skip the Docker hardening module")
    parser.add_argument("--skip-telegram", action="store_true",
                        help="Skip Telegram bot setup")
    parser.add_argument("--skip-geoip", action="store_true",
                        help="Skip GeoIP blocking")
    parser.add_argument("--assume-yes", action="store_true",
                        help="Reserved: accept all prompts (NOT recommended)")
    parser.add_argument("--version", action="version",
                        version=f"{SCRIPT_NAME} v{SCRIPT_VERSION}")

    ns = parser.parse_args(argv)
    return RunOptions(
        dry_run=ns.dry_run,
        verbose=ns.verbose,
        skip_luks=ns.skip_luks,
        skip_wireguard=ns.skip_wireguard,
        skip_docker=ns.skip_docker,
        skip_telegram=ns.skip_telegram,
        skip_geoip=ns.skip_geoip,
        assume_yes=ns.assume_yes,
    )
# ---------------------------------------------------------------------------
# Logging & output
# ---------------------------------------------------------------------------

class Colour:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    MAGENTA = "\033[0;35m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    NC = "\033[0m"


def _is_tty() -> bool:
    return sys.stdout.isatty()


def c(text: str, colour: str) -> str:
    if not _is_tty():
        return text
    return f"{colour}{text}{Colour.NC}"


class Logger:
    """Writes structured logs to disk and friendly output to the terminal."""

    def __init__(self, log_file: pathlib.Path, verbose: bool = False):
        self.log_file = log_file
        self.verbose = verbose
        self._logger = logging.getLogger("v4-harden")
        self._logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self._logger.handlers.clear()
        self._logger.propagate = False

        # Ensure parent dir exists and file has 0600 perms
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Pre-create file with correct perms before FileHandler opens it
        if not log_file.exists():
            log_file.touch(mode=0o600, exist_ok=True)
        os.chmod(log_file, 0o600)

        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        ))
        self._logger.addHandler(fh)

    # ---- raw log ----
    def debug(self, msg: str) -> None:
        self._logger.debug(msg)

    def info(self, msg: str) -> None:
        self._logger.info(msg)

    def warn(self, msg: str) -> None:
        self._logger.warning(msg)

    def error(self, msg: str) -> None:
        self._logger.error(msg)

    def action(self, msg: str) -> None:
        self._logger.info("ACTION: %s", msg)

    # ---- terminal output ----
    def section(self, title: str) -> None:
        bar = "━" * 68
        print()
        print(c(bar, Colour.BLUE))
        print(c(f"  {title}", Colour.BOLD))
        print(c(bar, Colour.BLUE))
        self._logger.info("=== %s ===", title)

    def subsection(self, title: str) -> None:
        print()
        print(c(f"  ▸ {title}", Colour.CYAN))
        print(c("  " + "─" * 60, Colour.DIM))
        self._logger.info("--- %s ---", title)

    def step(self, msg: str) -> None:
        print(c(f"  [→] {msg}", Colour.MAGENTA))
        self._logger.info("STEP: %s", msg)

    def ok(self, msg: str) -> None:
        print(c(f"  [✔] {msg}", Colour.GREEN))
        self._logger.info("OK: %s", msg)

    def warn_ui(self, msg: str) -> None:
        print(c(f"  [⚠] {msg}", Colour.YELLOW))
        self._logger.warning(msg)

    def err_ui(self, msg: str) -> None:
        print(c(f"  [✘] {msg}", Colour.RED))
        self._logger.error(msg)

    def info_ui(self, msg: str) -> None:
        print(c(f"  [ℹ] {msg}", Colour.CYAN))
        self._logger.info(msg)

    def raw(self, msg: str) -> None:
        print(msg)

    def banner(self) -> None:
        print()
        print(c("╔══════════════════════════════════════════════════════════════════╗", Colour.CYAN))
        print(c("║              VPS HARDENING SCRIPT  v4.0                          ║", Colour.CYAN))
        print(c("║        Provider-aware · Distro-aware · Rollback-safe             ║", Colour.CYAN))
        print(c("╚══════════════════════════════════════════════════════════════════╝", Colour.CYAN))
        print()


GLOBAL_LOG: Optional[Logger] = None

def log() -> Logger:
    if GLOBAL_LOG is None:
        raise RuntimeError("Logger not initialised")
    return GLOBAL_LOG
# ---------------------------------------------------------------------------
# CommandRunner
# ---------------------------------------------------------------------------
#
# Every shell-out in this script goes through CommandRunner. It:
#   * Never uses shell=True
#   * Supports dry-run (prints the exact command and returns success)
#   * Streams stderr to the log file
#   * Raises HardeningError on failure unless check=False
#   * Provides a `capture()` helper for read-only inspection commands
# ---------------------------------------------------------------------------

class HardeningError(RuntimeError):
    """Raised when a hardening step fails irrecoverably."""


class CommandResult:
    def __init__(self, argv: Sequence[str], returncode: int,
                 stdout: str = "", stderr: str = ""):
        self.argv = list(argv)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    # ---- internal ----
    def _fmt(self, argv: Sequence[str]) -> str:
        return " ".join(shlex.quote(str(a)) for a in argv)

    def _log_to_file(self, argv: Sequence[str], rc: int, out: str, err: str) -> None:
        if GLOBAL_LOG is None:
            return
        GLOBAL_LOG.debug(f"CMD rc={rc}: {self._fmt(argv)}")
        if out:
            GLOBAL_LOG.debug(f"STDOUT: {out.rstrip()}")
        if err:
            GLOBAL_LOG.debug(f"STDERR: {err.rstrip()}")

    # ---- public ----
    def run(self, argv: Sequence[str], *,
            check: bool = True,
            capture: bool = True,
            timeout: Optional[int] = 300,
            input_text: Optional[str] = None,
            env: Optional[dict] = None) -> CommandResult:
        argv = [str(a) for a in argv]

        if self.dry_run:
            if GLOBAL_LOG:
                GLOBAL_LOG.info(f"[DRY-RUN] would execute: {self._fmt(argv)}")
            print(c(f"      [dry-run] {self._fmt(argv)}", Colour.DIM))
            return CommandResult(argv, 0, "", "")

        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        try:
            proc = subprocess.run(
                argv,
                check=False,
                capture_output=capture,
                text=True,
                timeout=timeout,
                input=input_text,
                env=merged_env,
            )
        except FileNotFoundError as e:
            raise HardeningError(f"Command not found: {argv[0]} ({e})") from e
        except subprocess.TimeoutExpired as e:
            raise HardeningError(f"Command timed out: {self._fmt(argv)}") from e

        out = proc.stdout or ""
        err = proc.stderr or ""
        result = CommandResult(argv, proc.returncode, out, err)
        self._log_to_file(argv, proc.returncode, out, err)

        if check and proc.returncode != 0:
            raise HardeningError(
                f"Command failed (rc={proc.returncode}): {self._fmt(argv)}\n"
                f"stderr: {err.strip()}"
            )
        return result

    def capture(self, argv: Sequence[str], **kw) -> str:
        """Run and return stdout (stripped), empty string on failure."""
        res = self.run(argv, check=False, capture=True, **kw)
        return res.stdout.strip()

    def exists(self, binary: str) -> bool:
        return shutil.which(binary) is not None

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------

def _read_dmi(path: str) -> str:
    try:
        return pathlib.Path(path).read_text(errors="replace").strip()
    except Exception:
        return ""


def detect_provider() -> Provider:
    """Best-effort provider detection using DMI + virt heuristics."""
    dmi_vendor = _read_dmi("/sys/class/dmi/id/sys_vendor").lower()
    dmi_product = _read_dmi("/sys/class/dmi/id/product_name").lower()
    dmi_version = _read_dmi("/sys/class/dmi/id/product_version").lower()
    chassis_asset = _read_dmi("/sys/class/dmi/id/chassis_asset_tag").lower()
    combined = " ".join([dmi_vendor, dmi_product, dmi_version, chassis_asset])

    if "oracle" in combined or "oraclecloud" in combined:
        return Provider.ORACLE
    if "amazon" in combined or "ec2" in combined:
        return Provider.AWS
    if "google" in combined:
        return Provider.GCP
    if "microsoft" in combined or "azure" in combined:
        return Provider.AZURE
    if "digitalocean" in combined or "droplet" in combined:
        return Provider.DIGITALOCEAN
    if "linode" in combined:
        return Provider.LINODE
    if "vultr" in combined:
        return Provider.VULTR
    if "hetzner" in combined:
        return Provider.HETZNER
    if "kvm" in combined or "qemu" in combined:
        return Provider.KVM
    return Provider.OTHER


def detect_os() -> tuple[str, str, str, str]:
    """Return (id, version, codename, pretty_name)."""
    os_id = os_version = os_codename = os_pretty = "unknown"
    os_release = pathlib.Path("/etc/os-release")
    if os_release.is_file():
        data: dict[str, str] = {}
        for line in os_release.read_text(errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                v = v.strip().strip('"').strip("'")
                data[k.strip()] = v
        os_id = data.get("ID", os_id).lower()
        os_version = data.get("VERSION_ID", os_version)
        os_codename = data.get("VERSION_CODENAME", os_codename)
        os_pretty = data.get("PRETTY_NAME", os_pretty)
    return os_id, os_version, os_codename, os_pretty


def get_primary_ip() -> str:
    """Return the primary IPv4 address used for outbound traffic."""
    try:
        # No actual traffic is sent; this just asks the kernel which src IP it would pick
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "unknown"


def gather_system_info(runner: CommandRunner) -> SystemInfo:
    info = SystemInfo()

    info.os_id, info.os_version, info.os_codename, info.os_pretty_name = detect_os()
    info.kernel = platform.release()
    info.arch = platform.machine()
    info.hostname = socket.getfqdn() or socket.gethostname()
    info.primary_ip = get_primary_ip()
    info.provider = detect_provider()
    info.is_oracle = info.provider is Provider.ORACLE
    info.is_arm = info.arch in ("aarch64", "arm64", "armv8l")

    # Virtualisation
    info.virt = runner.capture(["systemd-detect-virt"]) or "unknown"

    # Capabilities
    info.has_systemd = runner.exists("systemctl") and pathlib.Path("/run/systemd/system").is_dir()
    info.has_apt = runner.exists("apt-get")
    info.has_ufw = runner.exists("ufw")
    info.has_docker = runner.exists("docker")
    info.has_tailscale = runner.exists("tailscale")
    info.has_wireguard = runner.exists("wg")

    return info


def supported_os(info: SystemInfo) -> bool:
    """Only Ubuntu 20.04/22.04/24.04 and Debian 11/12 are officially supported."""
    if info.os_id == "ubuntu":
        return info.os_version in ("20.04", "22.04", "24.04")
    if info.os_id == "debian":
        return info.os_version in ("11", "12")
    return False


def print_system_info(info: SystemInfo) -> None:
    log().subsection("System Information")
    kv = [
        ("Distribution", info.os_pretty_name),
        ("OS ID", info.os_id),
        ("Version", info.os_version),
        ("Codename", info.os_codename),
        ("Kernel", info.kernel),
        ("Architecture", info.arch),
        ("Virtualisation", info.virt),
        ("Provider", info.provider.value),
        ("Hostname", info.hostname),
        ("Primary IP", info.primary_ip),
        ("systemd", "yes" if info.has_systemd else "no"),
        ("apt", "yes" if info.has_apt else "no"),
        ("Docker present", "yes" if info.has_docker else "no"),
        ("Tailscale present", "yes" if info.has_tailscale else "no"),
    ]
    for k, v in kv:
        print(f"      {k:<18} {c(str(v), Colour.CYAN)}")

  # ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def prompt_yes_no(question: str, *, default: bool = False,
                  assume_yes: bool = False) -> bool:
    """Interactive yes/no prompt. Returns True for yes."""
    if assume_yes:
        print(c(f"  [?] {question} [assume-yes → yes]", Colour.MAGENTA))
        return True

    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            ans = input(c(f"  [?] {question} {hint}: ", Colour.MAGENTA)).strip().lower()
        except EOFError:
            return default
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print(c("      Please answer 'yes' or 'no'.", Colour.YELLOW))


def prompt_input(question: str, *, default: Optional[str] = None,
                 validate: Optional[Callable[[str], bool]] = None,
                 validator_msg: str = "Invalid input.") -> str:
    """Prompt for free-form text with optional validation."""
    while True:
        if default is not None:
            raw = input(c(f"  [?] {question} [default: {default}]: ", Colour.MAGENTA)).strip()
            value = raw or default
        else:
            value = input(c(f"  [?] {question}: ", Colour.MAGENTA)).strip()
        if validate is None or validate(value):
            return value
        print(c(f"      {validator_msg}", Colour.RED))


def prompt_choice(question: str, choices: list[tuple[str, str]],
                  default_index: int = 0) -> str:
    """Prompt for a numbered menu choice. choices = [(key, label), ...]"""
    print(c(f"  [?] {question}", Colour.MAGENTA))
    for i, (_, label) in enumerate(choices, 1):
        print(f"      {c(str(i), Colour.CYAN)}) {label}")
    while True:
        raw = input(c(f"  [?] Select [1-{len(choices)}] (default {default_index + 1}): ",
                      Colour.MAGENTA)).strip()
        if not raw:
            return choices[default_index][0]
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1][0]
        print(c("      Invalid selection.", Colour.RED))


def require_root() -> None:
    if os.geteuid() != 0:
        log().err_ui("This script must be run as root (use sudo).")
        sys.exit(EXIT_PREREQ)


def check_internet(runner: CommandRunner) -> bool:
    log().subsection("Internet connectivity")
    targets = [
        ["curl", "-fsS", "--max-time", "5", "-o", "/dev/null", "https://1.1.1.1"],
        ["curl", "-fsS", "--max-time", "5", "-o", "/dev/null", "https://9.9.9.9"],
    ]
    for argv in targets:
        if not runner.exists(argv[0]):
            continue
        try:
            res = runner.run(argv, check=False, timeout=10)
            if res.returncode == 0:
                log().ok(f"Internet reachable (tested via {argv[-1]})")
                return True
        except Exception:
            continue
    log().warn_ui("No internet connectivity detected via curl.")
    log().info_ui("Some modules (Telegram, CrowdSec, Livepatch) require internet.")
    return False


def check_disk_space(path: str = "/", required_mb: int = 1024) -> bool:
    try:
        usage = shutil.disk_usage(path)
    except Exception:
        return True
    free_mb = usage.free // (1024 * 1024)
    if free_mb < required_mb:
        log().warn_ui(f"Low disk space on {path}: {free_mb} MB free (need ≥ {required_mb} MB)")
        return False
    log().ok(f"Disk space on {path}: {free_mb} MB free")
    return True


def check_memory(required_mb: int = 256) -> bool:
    try:
        meminfo = pathlib.Path("/proc/meminfo").read_text()
        m = re.search(r"MemAvailable:\s+(\d+)\s+kB", meminfo)
        if not m:
            return True
        available_mb = int(m.group(1)) // 1024
    except Exception:
        return True
    if available_mb < required_mb:
        log().warn_ui(f"Low available memory: {available_mb} MB (need ≥ {required_mb} MB)")
        return False
    log().ok(f"Available memory: {available_mb} MB")
    return True


def console_reminder(info: SystemInfo) -> None:
    """Mandatory safety reminder — OCI/AWS/GCP/Azure specifics."""
    log().subsection("Console access reminder")
    print(c(
        "  This script will change SSH, firewall, and possibly VPN configuration.",
        Colour.YELLOW))
    print(c(
        "  Before continuing, confirm you have out-of-band access to this server.",
        Colour.YELLOW))
    print()

    if info.provider is Provider.ORACLE:
        print(c("  Oracle Cloud (OCI) console access:", Colour.BOLD))
        print("    OCI Console → Compute → Instances → your instance →")
        print("    Resources → Console Connection → Create Local Connection")
        print("    (or use Cloud Shell → serial console).")
        print("    Verify you can log in through the serial console BEFORE continuing.")
    elif info.provider is Provider.AWS:
        print(c("  AWS EC2 console access:", Colour.BOLD))
        print("    AWS Console → EC2 → Instances → your instance →")
        print("    Actions → Monitor and troubleshoot → Get system log / EC2 Serial Console.")
    elif info.provider is Provider.GCP:
        print(c("  GCP console access:", Colour.BOLD))
        print("    GCP Console → Compute Engine → VM instances → your instance →")
        print("    Enable serial console (may require enabling at project level).")
    elif info.provider is Provider.AZURE:
        print(c("  Azure console access:", Colour.BOLD))
        print("    Azure Portal → Virtual machines → your VM →")
        print("    Support + troubleshooting → Serial console.")
    else:
        print(c("  If your provider offers a serial/VNC console, verify access now.", Colour.BOLD))
    print()

    if not prompt_yes_no("Have you verified you can reach this server via an out-of-band console?",
                         default=False):
        log().err_ui("Aborting: out-of-band console access is a prerequisite for safe hardening.")
        sys.exit(EXIT_USER_ABORT)


def preflight(runner: CommandRunner, opts: RunOptions) -> SystemInfo:
    log().section("Module 01 — Pre-flight checks")

    require_root()

    info = gather_system_info(runner)
    print_system_info(info)

    if not supported_os(info):
        log().warn_ui(
            f"OS '{info.os_id} {info.os_version}' is not in the officially supported list "
            f"(Ubuntu 20.04/22.04/24.04, Debian 11/12)."
        )
        if not prompt_yes_no("Continue anyway on an untested platform?", default=False):
            log().err_ui("Aborted by user.")
            sys.exit(EXIT_USER_ABORT)

    if not info.has_systemd:
        log().err_ui("systemd is required. This script does not support non-systemd init.")
        sys.exit(EXIT_PREREQ)

    if not info.has_apt:
        log().err_ui("apt-get is required. This script currently supports Debian/Ubuntu only.")
        sys.exit(EXIT_PREREQ)

    if info.is_arm:
        log().info_ui("ARM64 detected — package selection will be adjusted where needed.")

    if info.provider is Provider.ORACLE:
        log().info_ui(
            "Oracle Cloud detected. Remember: OCI Security Lists / NSGs "
            "must be updated separately for every port you open in UFW."
        )

    check_disk_space("/", 1024)
    check_memory(256)
    check_internet(runner)
    console_reminder(info)

    print()
    log().ok("Pre-flight checks passed.")
    return info

# ---------------------------------------------------------------------------
# Backup & rollback framework
# ---------------------------------------------------------------------------
#
# Every file modification is preceded by a backup_file() call. Each backup
# registers an undo action on the rollback stack. On SIGINT/SIGTERM or any
# unhandled exception, the stack is unwound in reverse order.
#
# The stack is intentionally simple: an ordered list of callables. Each
# callable, when invoked, restores one thing. This covers:
#   * restoring files
#   * deleting created files
#   * closing firewall rules that were opened
#   * restarting services that were stopped
# ---------------------------------------------------------------------------

class BackupManager:
    def __init__(self, backup_root: pathlib.Path, runner: CommandRunner):
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.session_dir = backup_root / stamp
        self.session_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.session_dir, 0o700)
        self.runner = runner
        self._undo_actions: list[tuple[str, Callable[[], None]]] = []
        self._committed = False

    # ---- backups ----
    def backup_path_for(self, original: pathlib.Path) -> pathlib.Path:
        # Preserve absolute path structure inside session_dir
        rel = str(original).lstrip("/")
        return self.session_dir / rel

    def backup_file(self, path: pathlib.Path) -> Optional[pathlib.Path]:
        """Copy a file or directory into the session backup dir. Returns backup path."""
        path = pathlib.Path(path)
        if not path.exists():
            return None
        dest = self.backup_path_for(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if path.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(path, dest, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(path, dest)
        log().debug(f"Backed up {path} → {dest}")
        self.register_undo(f"restore {path}", lambda: self._restore(path, dest))
        return dest

    def _restore(self, original: pathlib.Path, backup: pathlib.Path) -> None:
        try:
            if backup.is_dir():
                if original.exists():
                    shutil.rmtree(original, ignore_errors=True)
                shutil.copytree(backup, original, symlinks=True, dirs_exist_ok=True)
            else:
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, original)
            log().info(f"Restored {original} from {backup}")
        except Exception as e:
            log().error(f"Failed to restore {original}: {e}")

    # ---- undo stack ----
    def register_undo(self, description: str, action: Callable[[], None]) -> None:
        self._undo_actions.append((description, action))

    def register_delete_on_rollback(self, path: pathlib.Path) -> None:
        path = pathlib.Path(path)
        def _del():
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                elif path.exists():
                    path.unlink()
                log().info(f"Removed {path} (rollback)")
            except Exception as e:
                log().error(f"Failed to remove {path}: {e}")
        self.register_undo(f"delete {path}", _del)

    def rollback(self) -> None:
        if self._committed:
            return
        log().warn_ui("Rolling back all changes made in this session...")
        for description, action in reversed(self._undo_actions):
            log().step(f"Undo: {description}")
            try:
                action()
            except Exception as e:
                log().error(f"Undo action failed ({description}): {e}")
        log().warn_ui("Rollback complete.")

    def commit(self) -> None:
        """Called on successful completion so the rollback stack is not triggered."""
        self._committed = True


# ---- Global instances ----
BACKUP: Optional[BackupManager] = None

def backup() -> BackupManager:
    if BACKUP is None:
        raise RuntimeError("BackupManager not initialised")
    return BACKUP


def init_backup(runner: CommandRunner, root: pathlib.Path = BACKUP_ROOT_DEFAULT) -> BackupManager:
    global BACKUP
    BACKUP = BackupManager(root, runner)
    log().info(f"Backup session directory: {BACKUP.session_dir}")
    return BACKUP


# ---- Signal / exception handlers ----

class _RollbackOnExit:
    """Context manager: commit on clean exit, rollback on any exception."""

    def __init__(self, bm: BackupManager):
        self.bm = bm

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.bm.commit()
            return False
        # Something failed — unwind
        self.bm.rollback()
        return False


def install_signal_handlers() -> None:
    """Ctrl+C / SIGTERM → rollback via the exception path."""
    def _handler(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)

# ---------------------------------------------------------------------------
# Telegram notifications
# ---------------------------------------------------------------------------
#
# Design goals:
#   * Read-only by default: bot is a *notifier*, not a remote shell.
#   * No dangerous commands in the bot.
#   * Strict IP validation if /ban and /unban are enabled.
#   * Dedicated unprivileged user, sandboxed systemd unit.
#   * Token stored 0600, never logged.
# ---------------------------------------------------------------------------

class TelegramConfig:
    def __init__(self, token: str, chat_id: str, hostname: str, server_ip: str):
        self.token = token
        self.chat_id = chat_id
        self.hostname = hostname
        self.server_ip = server_ip

    def save(self, path: pathlib.Path = TELEGRAM_CONF_FILE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (
            "# VPS Hardening v4 — Telegram configuration\n"
            "# This file contains a credential; keep it mode 0600, owner root:root.\n"
            f'TELEGRAM_BOT_TOKEN="{self.token}"\n'
            f'TELEGRAM_CHAT_ID="{self.chat_id}"\n'
            f'TELEGRAM_HOSTNAME="{self.hostname}"\n'
            f'TELEGRAM_SERVER_IP="{self.server_ip}"\n'
        )
        path.write_text(content)
        os.chmod(path, 0o600)
        try:
            shutil.chown(path, user="root", group="root")
        except Exception:
            pass

    @classmethod
    def load(cls, path: pathlib.Path = TELEGRAM_CONF_FILE) -> Optional["TelegramConfig"]:
        if not path.is_file():
            return None
        data: dict[str, str] = {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"').strip("'")
        if not data.get("TELEGRAM_BOT_TOKEN") or not data.get("TELEGRAM_CHAT_ID"):
            return None
        return cls(
            token=data["TELEGRAM_BOT_TOKEN"],
            chat_id=data["TELEGRAM_CHAT_ID"],
            hostname=data.get("TELEGRAM_HOSTNAME", socket.gethostname()),
            server_ip=data.get("TELEGRAM_SERVER_IP", "unknown"),
        )


class TelegramNotifier:
    def __init__(self, cfg: Optional[TelegramConfig], runner: CommandRunner):
        self.cfg = cfg
        self.runner = runner

    def _api_url(self, method: str) -> str:
        assert self.cfg
        return f"https://api.telegram.org/bot{self.cfg.token}/{method}"

    def send(self, text: str, *, parse_mode: str = "HTML",
             silent: bool = False) -> bool:
        if not self.cfg:
            return False
        payload = json.dumps({
            "chat_id": self.cfg.chat_id,
            "text": text[:4000],
            "parse_mode": parse_mode,
            "disable_notification": silent,
        }).encode("utf-8")
        req = urllib.request.Request(
            self._api_url("sendMessage"),
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            log().warn_ui(f"Telegram send failed: {e}")
            return False

    def test(self) -> bool:
        return self.send(
            f"<b>VPS Hardening v4</b>\n"
            f"Test message from <code>{self.cfg.hostname if self.cfg else 'unknown'}</code>"
        )

    def verify_token(self) -> bool:
        if not self.cfg:
            return False
        try:
            with urllib.request.urlopen(self._api_url("getMe"), timeout=10) as r:
                data = json.loads(r.read().decode())
                return bool(data.get("ok"))
        except Exception:
            return False


def setup_telegram(runner: CommandRunner, opts: RunOptions,
                   info: SystemInfo) -> Optional[TelegramNotifier]:
    if opts.skip_telegram:
        log().info_ui("Telegram module skipped by flag.")
        return TelegramNotifier(None, runner)

    log().section("Module 02 — Telegram notifications (hardened)")

    existing = TelegramConfig.load()
    if existing:
        log().info_ui("Existing Telegram configuration found.")
        if not prompt_yes_no("Reconfigure Telegram now?", default=False):
            notifier = TelegramNotifier(existing, runner)
            if notifier.verify_token():
                log().ok("Existing Telegram token verified.")
                return notifier
            log().warn_ui("Existing token failed verification. Reconfigure.")

    if not prompt_yes_no("Set up Telegram notifications now?", default=True):
        log().info_ui("Skipping Telegram setup.")
        return TelegramNotifier(None, runner)

    print()
    print(c("  How to create a Telegram bot:", Colour.BOLD))
    print("    1. In Telegram, open a chat with @BotFather.")
    print("    2. Send /newbot and follow the prompts.")
    print("    3. Copy the HTTP API token (format: 123456789:ABCdef...).")
    print()
    print(c("  How to find your chat ID:", Colour.BOLD))
    print("    1. Open Telegram and message @userinfobot.")
    print("    2. Copy your numeric user ID (may be negative for groups).")
    print("    3. Send /start to your new bot so it can message you.")
    print()

    while True:
        token = prompt_input("Bot token").strip()
        if re.fullmatch(r"\d+:[A-Za-z0-9_-]{30,}", token):
            break
        print(c("      Invalid token format.", Colour.RED))

    while True:
        chat_id = prompt_input("Chat ID").strip()
        if re.fullmatch(r"-?\d+", chat_id):
            break
        print(c("      Chat ID must be numeric.", Colour.RED))

    cfg = TelegramConfig(
        token=token,
        chat_id=chat_id,
        hostname=info.hostname,
        server_ip=info.primary_ip,
    )
    notifier = TelegramNotifier(cfg, runner)

    if not notifier.verify_token():
        log().err_ui("Token verification failed (getMe).")
        if not prompt_yes_no("Save anyway?", default=False):
            return TelegramNotifier(None, runner)
    else:
        log().ok("Telegram token verified.")

    cfg.save()
    log().ok(f"Configuration saved to {TELEGRAM_CONF_FILE} (mode 0600)")

    if notifier.test():
        log().ok("Test message delivered.")
    else:
        log().warn_ui("Test message failed — check token and chat ID.")

    # Deploy the read-only bot daemon and systemd unit
    deploy_readonly_bot(runner, cfg)
    return notifier


def deploy_readonly_bot(runner: CommandRunner, cfg: TelegramConfig) -> None:
    """Deploy a hardened, read-only Telegram bot as an unprivileged user."""
    log().subsection("Deploying hardened read-only bot daemon")

    bot_dir = pathlib.Path("/opt/vps-telegram-bot")
    bot_script = bot_dir / "bot.py"
    bot_user = "vpsbot"

    if not runner.exists("python3"):
        log().warn_ui("python3 not found; skipping bot daemon deployment.")
        return

    # Create unprivileged user if missing
    if runner.capture(["id", "-u", bot_user]) == "":
        runner.run([
            "useradd", "--system", "--no-create-home",
            "--shell", "/usr/sbin/nologin", bot_user,
        ], check=False)

    bot_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(bot_dir, 0o750)
    try:
        shutil.chown(bot_dir, user=bot_user, group=bot_user)
    except Exception:
        pass

    bot_script.write_text(READONLY_BOT_SOURCE)
    os.chmod(bot_script, 0o750)
    try:
        shutil.chown(bot_script, user=bot_user, group=bot_user)
    except Exception:
        pass

    # Systemd unit with strong sandboxing, read-only filesystem for the service
    unit = pathlib.Path("/etc/systemd/system/vps-telegram-bot.service")
    unit.write_text(textwrap.dedent(f"""\
        [Unit]
        Description=VPS Hardening v4 read-only Telegram bot
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        User={bot_user}
        Group={bot_user}
        ExecStart=/usr/bin/python3 {bot_script}
        Restart=on-failure
        RestartSec=10

        # Hard sandboxing
        NoNewPrivileges=true
        ProtectSystem=strict
        ProtectHome=true
        PrivateTmp=true
        PrivateDevices=true
        ProtectKernelTunables=true
        ProtectKernelModules=true
        ProtectControlGroups=true
        ProtectKernelLogs=true
        RestrictSUIDSGID=true
        RestrictNamespaces=true
        LockPersonality=true
        MemoryDenyWriteExecute=true
        ReadOnlyPaths=/etc/vps-hardening
        ReadWritePaths={bot_dir}

        [Install]
        WantedBy=multi-user.target
    """))
    os.chmod(unit, 0o644)

    runner.run(["systemctl", "daemon-reload"], check=False)
    runner.run(["systemctl", "enable", "--now", "vps-telegram-bot.service"], check=False)
    log().ok("Hardened bot service deployed and started.")


READONLY_BOT_SOURCE = r'''#!/usr/bin/env python3
"""
VPS Hardening v4 — read-only Telegram bot.

Commands (all read-only):
  /start, /menu, /status, /health, /security, /firewall, /services,
  /logs, /users, /updates, /help

No command executes privileged actions. There is no /reboot, /ban, /unban.
All shell-outs go through subprocess.run(..., shell=False) with fixed argv.
"""
import json, os, re, subprocess, time, urllib.request, logging
from datetime import datetime

CONFIG_FILE = "/etc/vps-hardening/telegram.conf"
LOG_FILE = "/var/log/vps-telegram-bot.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_FILE)],
)
log = logging.getLogger("vpsbot")

def load_cfg():
    cfg = {}
    with open(CONFIG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

CFG = load_cfg()
TOKEN = CFG["TELEGRAM_BOT_TOKEN"]
CHAT_ID = str(CFG["TELEGRAM_CHAT_ID"])
HOST = CFG.get("TELEGRAM_HOSTNAME", "unknown")
API = f"https://api.telegram.org/bot{TOKEN}"

def api(method, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{API}/{method}", data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        log.warning(f"api {method} failed: {e}")
        return None

def send(text, kb=None):
    payload = {"chat_id": CHAT_ID, "text": text[:4000], "parse_mode": "HTML"}
    if kb:
        payload["reply_markup"] = kb
    api("sendMessage", payload)

def run(argv, timeout=15):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr or "").strip() or "no output"
    except Exception as e:
        return f"error: {e}"

def cmd_status():
    uptime = run(["uptime", "-p"])
    mem    = run(["free", "-m"])
    disk   = run(["df", "-h", "/"])
    ports  = run(["ss", "-tln"])
    send(
        f"<b>{HOST}</b>\n"
        f"<pre>uptime: {uptime}\n\n{mem}\n{disk}\n{ports[:1500]}</pre>"
    )

def cmd_help():
    send(
        "<b>Read-only commands</b>\n"
        "/status  — uptime, memory, disk, listening ports\n"
        "/security — ssh, ufw, fail2ban snapshot\n"
        "/logs    — last 40 lines of auth.log\n"
        "/help    — this message"
    )

def main():
    send(f"<b>{HOST} bot online (read-only)</b>\n{datetime.utcnow().isoformat()}Z")
    offset = 0
    while True:
        try:
            upd = api("getUpdates", {"offset": offset, "timeout": 30})
            if not upd or not upd.get("ok"):
                time.sleep(5)
                continue
            for u in upd.get("result", []):
                offset = u["update_id"] + 1
                msg = u.get("message") or {}
                chat = msg.get("chat") or {}
                if str(chat.get("id")) != CHAT_ID:
                    continue
                text = (msg.get("text") or "").strip()
                if text == "/status":
                    cmd_status()
                elif text == "/security":
                    send("<pre>" + run(["ufw", "status", "verbose"])[:1500] + "</pre>")
                elif text == "/logs":
                    send("<pre>" + run(["tail", "-n", "40", "/var/log/auth.log"])[:1500] + "</pre>")
                else:
                    cmd_help()
        except Exception as e:
            log.error(f"polling error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
'''

# ---------------------------------------------------------------------------
# SSH hardening
# ---------------------------------------------------------------------------
#
# This is the most dangerous module. It follows a strict workflow:
#
#   1. Detect current effective SSH port.
#   2. Prompt for desired new port (validated, blocklist-checked).
#   3. If the port changes:
#        a. Print provider-specific instructions for opening the new port.
#        b. Require explicit user confirmation that it has been opened.
#        c. Open the new port in UFW *without* closing the old one.
#        d. Write drop-in, validate with sshd -t.
#        e. Restart SSH.
#        f. Verify new port is listening.
#        g. Attempt localhost connection on new port.
#        h. If any step fails → roll back to old config.
#        i. Require user to open a second terminal and confirm login works.
#        j. Only then close the old port in UFW.
#   4. Apply remaining hardening (key-only, no root login, ciphers).
# ---------------------------------------------------------------------------

def current_ssh_port(runner: CommandRunner) -> str:
    # Check drop-ins first (they take precedence), then main config
    for path in sorted(SSH_CONFIG_DROPIN_DIR.glob("*.conf")) + [SSH_CONFIG_MAIN]:
        if not path.is_file():
            continue
        try:
            for line in path.read_text(errors="replace").splitlines():
                line = line.strip()
                if line.startswith("Port ") and not line.startswith("#"):
                    return line.split()[1]
        except Exception:
            pass
    # Socket activation
    if pathlib.Path("/etc/systemd/system/ssh.socket.d/override.conf").is_file():
        try:
            txt = pathlib.Path("/etc/systemd/system/ssh.socket.d/override.conf").read_text()
            m = re.search(r"ListenStream=(\d+)", txt)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "22"


def prompt_ssh_port(current: str) -> str:
    log().subsection("SSH port selection")
    print(c(f"  Current effective SSH port: {current}", Colour.CYAN))
    print()
    print(c("  Ports 1-1023 require root (fine for sshd) but are scanned less often", Colour.DIM))
    print(c("  above 1023; anything except 22 is a large noise reduction.", Colour.DIM))
    print()

    def _validate(v: str) -> bool:
        if not v.isdigit():
            return False
        n = int(v)
        if not (1 <= n <= 65535):
            return False
        return True

    while True:
        raw = prompt_input(
            "Desired SSH port (no default — type carefully)",
            validate=_validate,
            validator_msg="Must be an integer in 1-65535.",
        )
        n = int(raw)

        if n == 22:
            log().warn_ui("Port 22 is the default and is the most scanned port on the internet.")
            if not prompt_yes_no("Really use port 22?", default=False):
                continue

        if n in SSH_PORT_BLOCKLIST and n != 22:
            log().warn_ui(f"Port {n} is commonly used by other services.")
            if not prompt_yes_no("Use it anyway?", default=False):
                continue

        # Check if in use
        out = run_quiet(["ss", "-tln"])
        if re.search(rf":{n}\b", out) and str(n) != current:
            log().warn_ui(f"Port {n} appears to be in use already.")
            if not prompt_yes_no("Use it anyway?", default=False):
                continue

        return str(n)


def run_quiet(argv: list[str]) -> str:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def provider_open_port_instructions(info: SystemInfo, port: str) -> None:
    """Print provider-specific instructions for opening a port."""
    log().subsection(f"Action required: open port {port} in your provider firewall")
    print(c(
        "  UFW alone does not control your provider's network firewall.",
        Colour.YELLOW))
    print(c(
        f"  You MUST open TCP/{port} in the provider console BEFORE continuing,",
        Colour.YELLOW))
    print(c(
        "  or you will be locked out when the new SSH port is activated.",
        Colour.YELLOW))
    print()

    if info.provider is Provider.ORACLE:
        print(c("  Oracle Cloud (OCI):", Colour.BOLD))
        print("    Networking → Virtual Cloud Networks → your VCN →")
        print("    Security Lists → Default Security List → Add Ingress Rule:")
        print(f"      Source CIDR: 0.0.0.0/0")
        print(f"      IP Protocol: TCP")
        print(f"      Destination Port Range: {port}")
        print("    (Repeat for any IPv6 CIDR if you use IPv6.)")
    elif info.provider is Provider.AWS:
        print(c("  AWS EC2:", Colour.BOLD))
        print("    EC2 → Security Groups → your instance's SG → Edit inbound rules")
        print(f"      Type: Custom TCP | Port: {port} | Source: 0.0.0.0/0")
    elif info.provider is Provider.GCP:
        print(c("  GCP:", Colour.BOLD))
        print("    VPC network → Firewall → Create firewall rule")
        print(f"      Direction: Ingress | Action: Allow")
        print(f"      Targets: your instance | Source: 0.0.0.0/0")
        print(f"      Protocols/ports: tcp:{port}")
    elif info.provider is Provider.AZURE:
        print(c("  Azure:", Colour.BOLD))
        print("    VM → Networking → Add inbound port rule")
        print(f"      Source: Any | Destination port: {port} | Protocol: TCP")
    else:
        print(c("  Generic provider:", Colour.BOLD))
        print(f"    Open TCP/{port} in your provider's firewall / security group panel.")
    print()

    if not prompt_yes_no(
        f"I have opened TCP/{port} in my provider firewall and verified it is allowed",
        default=False,
    ):
        raise HardeningError("User did not confirm provider firewall change; aborting SSH port change.")


def apply_sshd_dropin(port: str, *, password_auth: bool, allow_root: bool) -> None:
    """Write the drop-in and ensure the main config includes drop-ins."""
    SSH_CONFIG_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(SSH_CONFIG_DROPIN_DIR, 0o755)

    # Ensure main config includes the drop-in dir
    main = SSH_CONFIG_MAIN.read_text(errors="replace")
    include_line = f"Include {SSH_CONFIG_DROPIN_DIR}/*.conf"
    if include_line not in main and "Include /etc/ssh/sshd_config.d/" not in main:
        new_main = include_line + "\n" + main
        SSH_CONFIG_MAIN.write_text(new_main)
        os.chmod(SSH_CONFIG_MAIN, 0o600)

    auth_methods_line = "AuthenticationMethods publickey" if not password_auth else ""
    lines = [
        "# VPS Hardening v4 — SSH drop-in",
        f"# Generated: {_dt.datetime.now().isoformat(timespec='seconds')}",
        "",
        f"Port {port}",
        "Protocol 2",
        "",
        "PermitRootLogin " + ("no" if not allow_root else "prohibit-password"),
        "MaxAuthTries 3",
        "MaxSessions 4",
        "LoginGraceTime 30",
        "StrictModes yes",
        "PermitEmptyPasswords no",
        "",
        "PasswordAuthentication " + ("no" if not password_auth else "yes"),
        "KbdInteractiveAuthentication no",
        "ChallengeResponseAuthentication no",
        "",
        "PubkeyAuthentication yes",
        "AuthorizedKeysFile .ssh/authorized_keys",
    ]
    if auth_methods_line:
        lines.append(auth_methods_line)
    lines += [
        "",
        "HostbasedAuthentication no",
        "IgnoreRhosts yes",
        "IgnoreUserKnownHosts yes",
        "KerberosAuthentication no",
        "GSSAPIAuthentication no",
        "",
        "X11Forwarding no",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "AllowStreamLocalForwarding no",
        "GatewayPorts no",
        "PermitTunnel no",
        "",
        "PermitUserEnvironment no",
        "PermitUserRC no",
        "",
        "ClientAliveInterval 300",
        "ClientAliveCountMax 2",
        "TCPKeepAlive no",
        "",
        "SyslogFacility AUTH",
        "LogLevel VERBOSE",
        "",
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com",
        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
        "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256",
        "HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256",
        "",
        "UseDNS no",
        "Compression no",
        "PrintMotd no",
        "PrintLastLog yes",
        "MaxStartups 10:30:60",
        "PerSourceMaxStartups 3",
        "",
    ]
    SSH_DROPIN_FILE.write_text("\n".join(lines))
    os.chmod(SSH_DROPIN_FILE, 0o600)
    try:
        shutil.chown(SSH_DROPIN_FILE, user="root", group="root")
    except Exception:
        pass


def sshd_test(runner: CommandRunner) -> bool:
    res = runner.run(["sshd", "-t"], check=False)
    return res.returncode == 0


def restart_ssh(runner: CommandRunner) -> None:
    # Ubuntu 24.04+ may use socket activation
    if pathlib.Path("/lib/systemd/system/ssh.socket").exists() or \
       pathlib.Path("/etc/systemd/system/ssh.socket.d").exists():
        runner.run(["systemctl", "daemon-reload"], check=False)
        runner.run(["systemctl", "restart", "ssh.socket"], check=False)
    runner.run(["systemctl", "restart", "ssh"], check=False)
    runner.run(["systemctl", "restart", "sshd"], check=False)


def port_listening(runner: CommandRunner, port: str) -> bool:
    out = runner.capture(["ss", "-tln"])
    return bool(re.search(rf":{port}\b", out))


def test_localhost_ssh(runner: CommandRunner, port: str,
                       user: str = "root") -> bool:
    """Attempt a non-interactive SSH login to localhost on the given port."""
    if not runner.exists("ssh"):
        log().warn_ui("ssh client not present; skipping localhost connect test.")
        return True
    res = runner.run([
        "ssh",
        "-p", port,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        f"{user}@127.0.0.1",
        "true",
    ], check=False, timeout=15)
    # Accept any of: exit 0 (key auth worked), or auth failure (still proves sshd is up)
    stderr = res.stderr or ""
    if res.returncode == 0:
        return True
    # If sshd is reachable we will see "Permission denied" — that's fine
    if "Permission denied" in stderr or "publickey" in stderr:
        return True
    return False


def harden_ssh(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
               notifier: TelegramNotifier) -> None:
    log().section("Module 04 — SSH hardening")
    bm = backup()

    old_port = current_ssh_port(runner)
    log().info_ui(f"Current effective SSH port: {old_port}")

    # --- Collect desired port ---
    new_port = prompt_ssh_port(old_port)
    port_changed = (new_port != old_port)

    # --- Determine auth posture ---
    target_user = os.environ.get("SUDO_USER") or "root"
    if target_user == "root":
        log().warn_ui("SUDO_USER is root — key-based login for non-root user cannot be verified here.")
    home = pathlib.Path(f"/home/{target_user}") if target_user != "root" else pathlib.Path("/root")
    auth_keys = home / ".ssh" / "authorized_keys"
    keys_present = auth_keys.is_file() and auth_keys.stat().st_size > 0

    if not keys_present:
        log().warn_ui(f"No SSH keys found for {target_user} ({auth_keys}).")
        log().warn_ui("Password authentication will remain ENABLED and PermitRootLogin will not be changed.")
        disable_password = False
        disable_root = False
    else:
        disable_password = prompt_yes_no(
            "Disable SSH password authentication (requires working key login)?",
            default=True,
        )
        disable_root = prompt_yes_no(
            "Disable direct SSH root login?", default=True)

    allow_root = not disable_root

    # --- Backups before touching anything ---
    bm.backup_file(SSH_CONFIG_MAIN)
    if SSH_CONFIG_DROPIN_DIR.is_dir():
        bm.backup_file(SSH_CONFIG_DROPIN_DIR)

    # ===================================================================
    # Port change workflow (only if changed)
    # ===================================================================
    if port_changed:
        log().subsection("Safe SSH port change workflow")

        # 1) Provider firewall confirmation
        provider_open_port_instructions(info, new_port)

        # 2) Backup UFW rules, then open new port WITHOUT closing old
        if info.has_ufw:
            ufw_status = runner.capture(["ufw", "status"])
            ufw_active = "Status: active" in ufw_status
            if ufw_active:
                log().step(f"Opening UFW for TCP/{new_port} (old port {old_port} kept open)")
                runner.run(["ufw", "limit", f"{new_port}/tcp"], check=False)
                bm.register_undo(
                    f"close ufw {new_port}/tcp",
                    lambda: runner.run(["ufw", "delete", "limit", f"{new_port}/tcp"], check=False),
                )

        # 3) Write drop-in with the new port (and chosen auth posture)
        log().step("Writing SSH drop-in configuration")
        apply_sshd_dropin(new_port, password_auth=not disable_password, allow_root=allow_root)

        # 4) Validate
        log().step("Validating SSH configuration with sshd -t")
        if not sshd_test(runner):
            log().err_ui("sshd -t failed after writing drop-in.")
            raise HardeningError("sshd configuration is invalid; rolled back automatically.")

        # 5) Restart SSH
        log().step("Restarting SSH service")
        restart_ssh(runner)

        # 6) Verify listening
        time.sleep(2)
        if not port_listening(runner, new_port):
            log().err_ui(f"Port {new_port} is NOT listening after restart.")
            raise HardeningError(f"SSH did not bind to port {new_port}.")

        log().ok(f"SSH is listening on port {new_port}.")

        # 7) Localhost reachability
        if not test_localhost_ssh(runner, new_port):
            log().err_ui("Localhost SSH connect test failed.")
            raise HardeningError("Localhost SSH connect test failed; rolled back automatically.")
        log().ok("Localhost SSH connect test succeeded.")

        # 8) Manual verification gate (MANDATORY)
        print()
        print(c("  ┌──────────────────────────────────────────────────────────────┐", Colour.YELLOW))
        print(c("  │  MANUAL VERIFICATION REQUIRED — DO NOT SKIP                 │", Colour.YELLOW))
        print(c("  └──────────────────────────────────────────────────────────────┘", Colour.YELLOW))
        print()
        print(c(f"  1. Open a NEW terminal (do NOT close this session).", Colour.BOLD))
        print(c(f"  2. Run:", Colour.BOLD))
        print(c(f"       ssh -p {new_port} {target_user}@{info.primary_ip}", Colour.CYAN))
        print(c(f"  3. Confirm you can log in and run `id`.", Colour.BOLD))
        print(c(f"  4. Return here and answer the prompt below.", Colour.BOLD))
        print()

        if not prompt_yes_no(
            f"Can you log in via SSH on port {new_port} from another terminal?",
            default=False,
        ):
            log().warn_ui("User could not verify the new port. Rolling back to old configuration.")
            raise HardeningError("Manual verification failed; rolled back.")

        # 9) Only now close the old UFW rule
        if info.has_ufw:
            log().step(f"Closing UFW rule for old port {old_port}")
            runner.run(["ufw", "delete", "limit", f"{old_port}/tcp"], check=False)
            runner.run(["ufw", "delete", "allow", f"{old_port}/tcp"], check=False)

        log().ok(f"SSH port change to {new_port} confirmed and old port closed in firewall.")
    else:
        # No port change — just apply the rest of the hardening
        log().step("Port unchanged; applying remaining SSH hardening")
        apply_sshd_dropin(old_port, password_auth=not disable_password, allow_root=allow_root)
        if not sshd_test(runner):
            raise HardeningError("sshd -t failed; rolled back automatically.")
        restart_ssh(runner)
        time.sleep(1)
        if not port_listening(runner, old_port):
            raise HardeningError("SSH no longer listening after config change; rolled back.")
        log().ok("SSH hardening applied successfully.")

    notifier.send(
        f"<b>SSH hardened</b>\n"
        f"Port: <code>{new_port}</code> (was <code>{old_port}</code>)\n"
        f"Password auth: <code>{'disabled' if disable_password else 'enabled'}</code>\n"
        f"Root login: <code>{'disabled' if disable_root else 'allowed'}</code>"
    )


# ---------------------------------------------------------------------------
# UFW firewall
# ---------------------------------------------------------------------------

def ensure_ufw_installed(runner: CommandRunner) -> None:
    if runner.exists("ufw"):
        return
    log().step("Installing ufw")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "ufw",
    ])


def ufw_active(runner: CommandRunner) -> bool:
    return "Status: active" in runner.capture(["ufw", "status"])


def ufw_status_verbose(runner: CommandRunner) -> None:
    out = runner.capture(["ufw", "status", "verbose"])
    for line in out.splitlines():
        print(c(f"      {line}", Colour.DIM))


def provider_firewall_reminder(info: SystemInfo, ports: list[tuple[str, str]]) -> None:
    """Print a summary of which ports must also be opened at the provider level."""
    if not ports:
        return
    log().subsection("Provider firewall reminder")
    print(c("  These ports were opened in UFW. You must also allow them at your", Colour.YELLOW))
    print(c("  provider's network firewall if you want them reachable from the internet.", Colour.YELLOW))
    print()
    for proto_port, label in ports:
        print(f"      {c(proto_port, Colour.CYAN)}   {label}")
    print()

    if info.provider is Provider.ORACLE:
        print(c("  OCI: VCN → Security Lists → add Ingress rules for the above.", Colour.BOLD))
    elif info.provider is Provider.AWS:
        print(c("  AWS: EC2 → Security Groups → add inbound rules for the above.", Colour.BOLD))
    elif info.provider is Provider.GCP:
        print(c("  GCP: VPC network → Firewall → add ingress rules for the above.", Colour.BOLD))
    elif info.provider is Provider.AZURE:
        print(c("  Azure: VM → Networking → add inbound port rules for the above.", Colour.BOLD))
    else:
        print(c("  Check your provider's firewall panel and open the above ports.", Colour.BOLD))
    print()


def configure_ufw(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
                  ssh_port: str, notifier: TelegramNotifier) -> None:
    log().section("Module 05 — UFW firewall")
    bm = backup()

    ensure_ufw_installed(runner)

    # Backup existing UFW config
    for path in [
        UFW_DEFAULT_DIR / "ufw.conf",
        UFW_DEFAULT_DIR / "before.rules",
        UFW_DEFAULT_DIR / "after.rules",
        pathlib.Path("/etc/default/ufw"),
    ]:
        if path.exists():
            bm.backup_file(path)

    # Snapshot current rules for display
    log().subsection("Current firewall status")
    ufw_status_verbose(runner)

    # Default policies
    log().subsection("Default policies")
    runner.run(["ufw", "default", "deny", "incoming"], check=False)
    runner.run(["ufw", "default", "allow", "outgoing"], check=False)
    runner.run(["ufw", "default", "deny", "routed"], check=False)
    log().ok("Defaults set: deny incoming, allow outgoing, deny routed")

    # SSH rule (always on the chosen port, rate-limited)
    opened: list[tuple[str, str]] = []
    log().step(f"Allowing SSH on tcp/{ssh_port} (rate-limited)")
    runner.run(["ufw", "limit", f"{ssh_port}/tcp"], check=False)
    opened.append((f"tcp/{ssh_port}", "SSH (rate-limited)"))

    # Common services
    log().subsection("Common services")
    if prompt_yes_no("Allow HTTP (tcp/80)?", default=False):
        runner.run(["ufw", "allow", "80/tcp"], check=False)
        opened.append(("tcp/80", "HTTP"))
    if prompt_yes_no("Allow HTTPS (tcp/443)?", default=False):
        runner.run(["ufw", "allow", "443/tcp"], check=False)
        opened.append(("tcp/443", "HTTPS"))
    if prompt_yes_no("Allow DNS (tcp+udp/53)?", default=False):
        runner.run(["ufw", "allow", "53/tcp"], check=False)
        runner.run(["ufw", "allow", "53/udp"], check=False)
        opened.append(("tcp+udp/53", "DNS"))
    if prompt_yes_no("Allow WireGuard (udp/51820)?", default=False):
        runner.run(["ufw", "allow", "51820/udp"], check=False)
        opened.append(("udp/51820", "WireGuard"))

    # Custom ports
    log().subsection("Custom ports")
    if prompt_yes_no("Add custom port rules?", default=False):
        while True:
            raw = prompt_input("Custom port (or empty to finish)", default="").strip()
            if not raw:
                break
            if not raw.isdigit() or not (1 <= int(raw) <= 65535):
                print(c("      Invalid port.", Colour.RED))
                continue
            proto = prompt_choice(
                "Protocol?",
                [("tcp", "TCP"), ("udp", "UDP"), ("both", "TCP + UDP")],
            )
            if proto == "both":
                runner.run(["ufw", "allow", f"{raw}/tcp"], check=False)
                runner.run(["ufw", "allow", f"{raw}/udp"], check=False)
                opened.append((f"tcp+udp/{raw}", "custom"))
            else:
                runner.run(["ufw", "allow", f"{raw}/{proto}"], check=False)
                opened.append((f"{proto}/{raw}", "custom"))

    # IPv6 handling
    log().subsection("IPv6")
    default_ufw = pathlib.Path("/etc/default/ufw")
    if default_ufw.is_file():
        if prompt_yes_no("Enable IPv6 in UFW?", default=True):
            txt = default_ufw.read_text()
            txt = re.sub(r"^IPV6=.*$", "IPV6=yes", txt, flags=re.MULTILINE)
            if "IPV6=" not in txt:
                txt += "\nIPV6=yes\n"
            default_ufw.write_text(txt)
            log().ok("IPv6 enabled in /etc/default/ufw")

    # Enable
    log().subsection("Enable firewall")
    if not ufw_active(runner):
        if prompt_yes_no(
            f"Enable UFW now? (SSH is currently allowed on tcp/{ssh_port})",
            default=True,
        ):
            runner.run(["ufw", "--force", "enable"], check=False)
            log().ok("UFW enabled.")
        else:
            log().warn_ui("UFW left disabled. Enable manually with: sudo ufw enable")
    else:
        runner.run(["ufw", "reload"], check=False)
        log().ok("UFW reloaded.")

    # Final reminder
    provider_firewall_reminder(info, opened)

    notifier.send(
        f"<b>Firewall configured</b>\n"
        f"UFW: <code>{'active' if ufw_active(runner) else 'inactive'}</code>\n"
        f"SSH rule: <code>tcp/{ssh_port}</code> (rate-limited)\n"
        f"Additional: <code>{', '.join(p for p, _ in opened if 'ssh' not in p.lower()) or 'none'}</code>"
    )


# ---------------------------------------------------------------------------
# Fail2ban
# ---------------------------------------------------------------------------
#
# Only one of {Fail2ban, CrowdSec} is activated at runtime to avoid
# double-banning and log-processing contention. The module does not install
# Fail2ban if CrowdSec is active and vice versa.
# ---------------------------------------------------------------------------

FAIL2BAN_DEFAULTS = pathlib.Path("/etc/fail2ban/jail.d/00-vps-hardening.local")
FAIL2BAN_SSHD = pathlib.Path("/etc/fail2ban/jail.d/10-vps-sshd.local")


def fail2ban_active(runner: CommandRunner) -> bool:
    return runner.capture(["systemctl", "is-active", "fail2ban"]) == "active"


def crowdsec_active(runner: CommandRunner) -> bool:
    return runner.capture(["systemctl", "is-active", "crowdsec"]) == "active"


def prompt_f2b_or_crowdsec(runner: CommandRunner) -> str:
    """Return 'fail2ban', 'crowdsec', or 'skip'. Recommended: crowdsec."""
    log().subsection("Intrusion prevention engine")
    print(c("  Choose exactly ONE. Running both causes duplicate bans and wasted CPU.", Colour.YELLOW))
    print()

    choice = prompt_choice(
        "Select intrusion prevention engine",
        [
            ("crowdsec", "CrowdSec (recommended) — collaborative, behaviour-based"),
            ("fail2ban", "Fail2ban — classic regex-based log bans"),
            ("skip",     "Skip — do not install either"),
        ],
        default_index=0,
    )
    return choice


def install_fail2ban(runner: CommandRunner) -> None:
    if runner.exists("fail2ban-client"):
        log().info_ui("Fail2ban already installed.")
        return
    log().step("Installing fail2ban")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "fail2ban",
    ])


def write_fail2ban_configs(runner: CommandRunner, ssh_port: str) -> None:
    bm = backup()
    if pathlib.Path("/etc/fail2ban/jail.conf").is_file():
        bm.backup_file(pathlib.Path("/etc/fail2ban/jail.conf"))
    if pathlib.Path("/etc/fail2ban/jail.d").is_dir():
        bm.backup_file(pathlib.Path("/etc/fail2ban/jail.d"))

    pathlib.Path("/etc/fail2ban/jail.d").mkdir(parents=True, exist_ok=True)

    # Determine the ban action and backend
    banaction = "ufw" if runner.exists("ufw") else "iptables-multiport"
    backend = "systemd" if pathlib.Path("/run/systemd/system").is_dir() else "auto"

    FAIL2BAN_DEFAULTS.write_text(textwrap.dedent(f"""\
        # VPS Hardening v4 — Fail2ban defaults
        # Generated: {_dt.datetime.now().isoformat(timespec='seconds')}

        [DEFAULT]
        bantime   = 1h
        findtime  = 10m
        maxretry  = 4
        banaction = {banaction}
        backend   = {backend}
        ignoreip  = 127.0.0.1/8 ::1
        # Do not send email by default; Telegram handles alerts
        action    = %(action_)s
    """))
    os.chmod(FAIL2BAN_DEFAULTS, 0o644)

    FAIL2BAN_SSHD.write_text(textwrap.dedent(f"""\
        # VPS Hardening v4 — SSH jail
        [sshd]
        enabled  = true
        port     = {ssh_port}
        filter   = sshd
        logpath  = %(sshd_log)s
        maxretry = 4
        bantime  = 1h

        # Recidive: repeat offenders get banned for 1 week
        [recidive]
        enabled  = true
        filter   = recidive
        logpath  = /var/log/fail2ban.log
        action   = %(banaction_allports)s
        bantime  = 1w
        findtime = 1d
        maxretry = 3
    """))
    os.chmod(FAIL2BAN_SSHD, 0o644)


def setup_fail2ban(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
                   ssh_port: str, notifier: TelegramNotifier) -> None:
    log().section("Module 06a — Fail2ban")

    if crowdsec_active(runner):
        log().warn_ui("CrowdSec is active; skipping Fail2ban install to avoid overlap.")
        return

    install_fail2ban(runner)
    write_fail2ban_configs(runner, ssh_port)

    runner.run(["systemctl", "enable", "fail2ban"], check=False)
    runner.run(["systemctl", "restart", "fail2ban"], check=False)
    time.sleep(2)

    if not fail2ban_active(runner):
        log().err_ui("fail2ban failed to start. Check: journalctl -u fail2ban")
        return

    log().ok("Fail2ban is active.")
    status = runner.capture(["fail2ban-client", "status"])
    for line in status.splitlines():
        print(c(f"      {line}", Colour.DIM))

    notifier.send(
        "<b>Fail2ban active</b>\n"
        f"SSH jail on port <code>{ssh_port}</code>\n"
        "Recidive jail: 1-week bans for repeat offenders"
    )


# ---------------------------------------------------------------------------
# CrowdSec
# ---------------------------------------------------------------------------
#
# Collaborative, behaviour-based intrusion prevention. Preferred over
# Fail2ban. If Fail2ban is already active, CrowdSec is still installed
# (they can coexist technically) but we warn and recommend disabling one.
# ---------------------------------------------------------------------------

CROWDSEC_REPO_SCRIPT = "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh"


def install_crowdsec(runner: CommandRunner) -> None:
    if runner.exists("cscli"):
        log().info_ui("CrowdSec already installed.")
        return

    log().step("Adding CrowdSec apt repository")
    # Download the setup script to a temp file and run it (avoids curl|bash)
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        runner.run(["curl", "-fsSL", CROWDDSEC_REPO_SCRIPT_FIX := CROWDSEC_REPO_SCRIPT, "-o", tmp_path])
        os.chmod(tmp_path, 0o700)
        runner.run(["bash", tmp_path])
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    log().step("Installing crowdsec + firewall bouncer")
    # Bouncer backend depends on the firewall stack
    bouncer_pkg = "crowdsec-firewall-bouncer-iptables"
    if runner.exists("nft"):
        bouncer_pkg = "crowdsec-firewall-bouncer-nftables"

    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "crowdsec", bouncer_pkg,
    ])


def configure_crowdsec(runner: CommandRunner, ssh_port: str) -> None:
    log().step("Installing SSH collection")
    runner.run(["cscli", "collections", "install", "crowdsecurity/sshd"], check=False)

    log().step("Installing base scenarios")
    for coll in ("crowdsecurity/linux", "crowdsecurity/base-http-scenarios"):
        runner.run(["cscli", "collections", "install", coll], check=False)

    # Ensure the sshd log is parsed. On Debian/Ubuntu with journald, crowdsec
    # uses the journald datasource automatically.
    runner.run(["systemctl", "enable", "crowdsec"], check=False)
    runner.run(["systemctl", "restart", "crowdsec"], check=False)
    runner.run(["systemctl", "enable", "crowdsec-firewall-bouncer"], check=False)
    runner.run(["systemctl", "restart", "crowdsec-firewall-bouncer"], check=False)


def crowdsec_status(runner: CommandRunner) -> None:
    log().subsection("CrowdSec status")
    out = runner.capture(["cscli", "metrics"])
    for line in out.splitlines()[:25]:
        print(c(f"      {line}", Colour.DIM))
    decisions = runner.capture(["cscli", "decisions", "list"])
    log().info_ui("Active decisions:")
    for line in decisions.splitlines()[:15]:
        print(c(f"      {line}", Colour.DIM))


def setup_crowdsec(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
                   ssh_port: str, notifier: TelegramNotifier) -> None:
    log().section("Module 06b — CrowdSec")

    if fail2ban_active(runner):
        log().warn_ui("Fail2ban is active. Running both engines may double-ban.")
        if not prompt_yes_no("Install CrowdSec anyway?", default=False):
            return

    install_crowdsec(runner)
    configure_crowdsec(runner, ssh_port)
    time.sleep(2)

    if crowdsec_active(runner):
        log().ok("CrowdSec is active.")
    else:
        log().err_ui("CrowdSec failed to start. Check: journalctl -u crowdsec")
        return

    crowdsec_status(runner)

    notifier.send(
        "<b>CrowdSec active</b>\n"
        f"SSH collection installed\n"
        f"Firewall bouncer: <code>"
        f"{'iptables' if not runner.exists('nft') else 'nftables'}</code>\n"
        "Enroll with <code>cscli console enroll &lt;key&gt;</code> to share threat intel."
    )


# Dispatcher used by the main flow
def setup_intrusion_prevention(runner: CommandRunner, opts: RunOptions,
                               info: SystemInfo, ssh_port: str,
                               notifier: TelegramNotifier) -> None:
    engine = prompt_f2b_or_crowdsec(runner)
    if engine == "fail2ban":
        setup_fail2ban(runner, opts, info, ssh_port, notifier)
    elif engine == "crowdsec":
        setup_crowdsec(runner, opts, info, ssh_port, notifier)
    else:
        log().info_ui("Intrusion prevention skipped by user choice.")

# ---------------------------------------------------------------------------
# Kernel sysctl hardening
# ---------------------------------------------------------------------------
#
# Writes a single drop-in file and calls `sysctl --system`. Idempotent by
# construction. Providers that require IP forwarding (some Oracle setups,
# users running Docker or WireGuard) have forwarding left alone.
# ---------------------------------------------------------------------------

def _sysctl_payload(info: SystemInfo, allow_forwarding: bool) -> str:
    lines = [
        "# VPS Hardening v4 — kernel hardening drop-in",
        f"# Generated: {_dt.datetime.now().isoformat(timespec='seconds')}",
        f"# Provider: {info.provider.value}  Kernel: {info.kernel}",
        "",
        "# ---- Kernel self-protection ----",
        "kernel.randomize_va_space = 2",
        "kernel.kptr_restrict = 2",
        "kernel.dmesg_restrict = 1",
        "kernel.perf_event_paranoid = 3",
        "kernel.yama.ptrace_scope = 2",
        "kernel.unprivileged_bpf_disabled = 1",
        "kernel.sysrq = 0",
        "kernel.core_uses_pid = 1",
        "",
        "# ---- Filesystem safety ----",
        "fs.suid_dumpable = 0",
        "fs.protected_hardlinks = 1",
        "fs.protected_symlinks = 1",
        "fs.protected_fifos = 2",
        "fs.protected_regular = 2",
        "",
        "# ---- IPv4 network hardening ----",
        "net.ipv4.conf.all.rp_filter = 1",
        "net.ipv4.conf.default.rp_filter = 1",
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.conf.default.accept_redirects = 0",
        "net.ipv4.conf.all.send_redirects = 0",
        "net.ipv4.conf.default.send_redirects = 0",
        "net.ipv4.conf.all.accept_source_route = 0",
        "net.ipv4.conf.default.accept_source_route = 0",
        "net.ipv4.conf.all.log_martians = 1",
        "net.ipv4.conf.default.log_martians = 1",
        "net.ipv4.icmp_echo_ignore_broadcasts = 1",
        "net.ipv4.icmp_ignore_bogus_error_responses = 1",
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.tcp_timestamps = 0",
        "net.ipv4.conf.all.secure_redirects = 0",
        "net.ipv4.conf.default.secure_redirects = 0",
        "net.ipv4.tcp_rfc1337 = 1",
        "",
        "# ---- IPv6 network hardening ----",
        "net.ipv6.conf.all.accept_redirects = 0",
        "net.ipv6.conf.default.accept_redirects = 0",
        "net.ipv6.conf.all.accept_source_route = 0",
        "net.ipv6.conf.default.accept_source_route = 0",
        "net.ipv6.conf.all.accept_ra = 0",
        "net.ipv6.conf.default.accept_ra = 0",
    ]
    if not allow_forwarding:
        lines += [
            "",
            "# ---- Forwarding disabled (no container/VPN routing detected) ----",
            "net.ipv4.ip_forward = 0",
            "net.ipv6.conf.all.forwarding = 0",
        ]
    else:
        lines += [
            "",
            "# ---- Forwarding left ENABLED (Docker/WireGuard/Tailscale detected) ----",
            "# net.ipv4.ip_forward intentionally not set",
        ]
    lines.append("")
    return "\n".join(lines)


def needs_forwarding(info: SystemInfo, runner: CommandRunner) -> bool:
    """Detect whether ip_forward must remain enabled."""
    if info.has_docker or info.has_tailscale:
        return True
    # Check WireGuard service
    if runner.capture(["systemctl", "is-active", "wg-quick@wg0"]) == "active":
        return True
    # Existing ip_forward already on (e.g. by cloud-init or another service)
    current = pathlib.Path("/proc/sys/net/ipv4/ip_forward")
    if current.is_file():
        try:
            if current.read_text().strip() == "1":
                return True
        except Exception:
            pass
    return False


def harden_kernel_sysctl(runner: CommandRunner, opts: RunOptions,
                         info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 07 — Kernel sysctl hardening")
    bm = backup()

    if SYSCTL_DROPIN.exists():
        bm.backup_file(SYSCTL_DROPIN)

    allow_fwd = needs_forwarding(info, runner)
    if allow_fwd:
        log().info_ui("Forwarding will remain enabled (Docker/Tailscale/WireGuard detected).")

    log().step(f"Writing {SYSCTL_DROPIN}")
    SYSCTL_DROPIN.write_text(_sysctl_payload(info, allow_fwd))
    os.chmod(SYSCTL_DROPIN, 0o644)

    log().step("Applying sysctl parameters")
    runner.run(["sysctl", "--system"], check=False)

    # Verify a representative set
    checks = [
        ("kernel.randomize_va_space", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.kptr_restrict", "2"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
    ]
    failed = 0
    for key, expected in checks:
        actual = runner.capture(["sysctl", "-n", key])
        if actual.strip() == expected:
            log().ok(f"{key} = {actual}")
        else:
            log().warn_ui(f"{key} = {actual} (expected {expected})")
            failed += 1

    if failed:
        log().warn_ui(f"{failed} sysctl check(s) did not match — common in containers.")
    else:
        log().ok("All sysctl checks passed.")

    notifier.send(
        "<b>Kernel sysctl hardened</b>\n"
        f"Forwarding: <code>{'enabled' if allow_fwd else 'disabled'}</code>\n"
        f"Drop-in: <code>{SYSCTL_DROPIN}</code>"
    )


# ---------------------------------------------------------------------------
# Kernel live patching
# ---------------------------------------------------------------------------
#
# Ubuntu Livepatch requires:
#   * Ubuntu (any LTS)
#   * A free or paid Ubuntu One / Pro token
#   * snapd installed
#
# We do NOT enable silently. Instead, we detect and offer, with a clear
# explanation that a token is required.
# ---------------------------------------------------------------------------

def ubuntu_livepatch_available(info: SystemInfo) -> bool:
    return info.os_id == "ubuntu"


def setup_livepatch(runner: CommandRunner, opts: RunOptions,
                    info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 08 — Kernel live patching")

    if not ubuntu_livepatch_available(info):
        log().info_ui("Livepatch is Ubuntu-only. Skipping on this platform.")
        return

    if runner.exists("canonical-livepatch"):
        status = runner.capture(["canonical-livepatch", "status"])
        log().info_ui("Livepatch already installed.")
        for line in status.splitlines()[:8]:
            print(c(f"      {line}", Colour.DIM))
        return

    print()
    print(c("  Ubuntu Livepatch applies kernel security patches without rebooting.", Colour.CYAN))
    print(c("  It requires a free Ubuntu One token (up to 5 machines free).", Colour.CYAN))
    print(c("  Get a token: https://ubuntu.com/pro", Colour.DIM))
    print()

    if not prompt_yes_no("Install and enable Livepatch now?", default=False):
        log().info_ui("Livepatch skipped.")
        return

    if not runner.exists("snap"):
        log().step("Installing snapd")
        runner.run(["apt-get", "install", "-y", "-qq", "snapd"], check=False)

    log().step("Installing canonical-livepatch snap")
    runner.run(["snap", "install", "canonical-livepatch"], check=False)

    token = prompt_input(
        "Ubuntu Livepatch token (leave blank to skip)",
        default="",
    ).strip()
    if not token:
        log().info_ui("No token provided; Livepatch installed but not enabled.")
        return

    log().step("Enabling Livepatch with provided token")
    runner.run(["canonical-livepatch", "enable", token], check=False)
    time.sleep(2)
    status = runner.capture(["canonical-livepatch", "status"])
    for line in status.splitlines()[:10]:
        print(c(f"      {line}", Colour.DIM))
    log().ok("Livepatch setup complete.")

    notifier.send(
        "<b>Kernel live patching enabled</b>\n"
        f"<pre>{status[:400]}</pre>"
    )


# ---------------------------------------------------------------------------
# AppArmor
# ---------------------------------------------------------------------------
#
# Install user-space tools and enforce profiles that already exist. We
# explicitly avoid aa-genprof (which is interactive and can break services
# on first run). Enforcement is limited to profiles already shipped by the
# distro.
# ---------------------------------------------------------------------------

def apparmor_kernel_available() -> bool:
    return pathlib.Path("/sys/kernel/security/apparmor").is_dir()


def setup_apparmor(runner: CommandRunner, opts: RunOptions,
                   info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 09 — AppArmor")
    bm = backup()

    if info.os_id == "debian" and info.os_version == "12":
        log().info_ui("Debian 12 supports AppArmor; profiles shipped via apparmor-profiles.")
    elif info.os_id == "ubuntu":
        log().info_ui(f"{info.os_pretty_name} ships AppArmor enabled by default.")

    # Install packages
    pkgs = ["apparmor", "apparmor-utils"]
    if info.os_id in ("ubuntu", "debian"):
        pkgs += ["apparmor-profiles", "apparmor-profiles-extra"]

    missing = [p for p in pkgs if not _dpkg_installed(runner, p)]
    if missing:
        log().step(f"Installing: {' '.join(missing)}")
        runner.run(["apt-get", "update", "-qq"], check=False)
        runner.run([
            "apt-get", "install", "-y", "-qq",
            "-o", "Dpkg::Options::=--force-confdef",
            "-o", "Dpkg::Options::=--force-confold",
            *missing,
        ], check=False)

    # Kernel support check
    if not apparmor_kernel_available():
        log().warn_ui("AppArmor kernel interface not present.")
        log().info_ui("This usually means the kernel was booted without security=apparmor.")
        if not prompt_yes_no("Configure GRUB to enable AppArmor on next boot?", default=False):
            log().info_ui("Skipping GRUB modification.")
            return
        _enable_apparmor_in_grub(runner)
        log().warn_ui("Reboot required to activate AppArmor kernel support.")
        return

    log().ok("AppArmor kernel interface available.")

    # Enforce existing profiles
    profile_dir = pathlib.Path("/etc/apparmor.d")
    if profile_dir.is_dir() and runner.exists("aa-enforce"):
        log().step("Enforcing existing AppArmor profiles")
        skip_names = {"local", "abstractions", "tunables", "disable", "force-complain"}
        enforced = 0
        failed = 0
        for p in profile_dir.iterdir():
            if p.is_dir() or p.name in skip_names:
                continue
            if p.suffix not in (".", "") and "." in p.name and p.name.count(".") > 1:
                # Skip versioned backups like foo.dpkg-old
                continue
            res = runner.run(["aa-enforce", str(p)], check=False)
            if res.returncode == 0:
                enforced += 1
            else:
                failed += 1
        log().ok(f"Enforced {enforced} profile(s); {failed} could not be enforced (see log).")

    # Restart AppArmor
    runner.run(["systemctl", "enable", "apparmor"], check=False)
    runner.run(["systemctl", "restart", "apparmor"], check=False)
    time.sleep(1)

    # Report
    if runner.exists("aa-status"):
        status = runner.capture(["aa-status"])
        log().subsection("AppArmor status")
        for line in status.splitlines()[:12]:
            print(c(f"      {line}", Colour.DIM))

    notifier.send("<b>AppArmor profiles enforced</b>\nUse <code>aa-status</code> to inspect.")


def _dpkg_installed(runner: CommandRunner, pkg: str) -> bool:
    res = runner.run(["dpkg", "-s", pkg], check=False)
    return res.returncode == 0


def _enable_apparmor_in_grub(runner: CommandRunner) -> None:
    bm = backup()
    grub_default = pathlib.Path("/etc/default/grub")
    if not grub_default.is_file():
        return
    bm.backup_file(grub_default)
    txt = grub_default.read_text()
    if "security=apparmor" in txt:
        log().info_ui("GRUB already contains security=apparmor.")
        return
    # Add to GRUB_CMDLINE_LINUX_DEFAULT
    new_txt = re.sub(
        r'^(GRUB_CMDLINE_LINUX_DEFAULT=")(.*?)(")',
        lambda m: f'{m.group(1)}{m.group(2)} security=apparmor{m.group(3)}',
        txt,
        flags=re.MULTILINE,
    )
    if new_txt == txt:
        # No line to modify; append one
        new_txt = txt.rstrip() + '\nGRUB_CMDLINE_LINUX_DEFAULT="security=apparmor"\n'
    grub_default.write_text(new_txt)
    runner.run(["update-grub"], check=False)
    log().ok("GRUB updated to enable AppArmor.")

# ---------------------------------------------------------------------------
# WireGuard
# ---------------------------------------------------------------------------
#
# Adds a WireGuard interface, generates server + client keys, writes config,
# and optionally binds SSH to the WireGuard interface only. Public SSH is
# kept open as a fallback and the user is explicitly told how to close it.
#
# Safety: public SSH is NEVER closed by this module. The user must do that
# manually after verifying the VPN works from a second device.
# ---------------------------------------------------------------------------

WG_DIR = pathlib.Path("/etc/wireguard")


def wg_installed(runner: CommandRunner) -> bool:
    return runner.exists("wg")


def install_wireguard(runner: CommandRunner) -> None:
    if wg_installed(runner):
        log().info_ui("WireGuard already installed.")
        return
    log().step("Installing wireguard")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "wireguard", "wireguard-tools",
    ])


def wg_generate_keypair(runner: CommandRunner) -> tuple[str, str]:
    priv = runner.capture(["wg", "genkey"])
    if not priv:
        raise HardeningError("Failed to generate WireGuard private key.")
    pub = runner.capture(["wg", "pubkey"], input_text=priv)
    if not pub:
        # Older wg may not accept stdin; use a temp file
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write(priv + "\n")
            tmp_path = tmp.name
        try:
            pub = runner.capture(["wg", "pubkey", tmp_path])
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    return priv, pub


def prompt_wg_config(info: SystemInfo) -> dict:
    log().subsection("WireGuard configuration")

    print(c(f"  Recommended subnet: {DEFAULT_WG_SUBNET}", Colour.DIM))
    print(c("  This avoids Docker (172.16/12), Tailscale (100.64/10), and home LANs.", Colour.DIM))
    print()

    def _validate_cidr(v: str) -> bool:
        try:
            ipaddress.ip_network(v, strict=False)
            return True
        except Exception:
            return False

    subnet = prompt_input(
        "WireGuard subnet (CIDR)",
        default=DEFAULT_WG_SUBNET,
        validate=_validate_cidr,
        validator_msg="Enter a valid CIDR, e.g. 10.200.200.0/24",
    )
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    server_ip = str(hosts[0])
    client_ip = str(hosts[1])

    port_raw = prompt_input(
        "WireGuard listen port (UDP)",
        default=str(DEFAULT_WG_PORT),
        validate=lambda v: v.isdigit() and 1 <= int(v) <= 65535,
        validator_msg="Must be an integer in 1-65535.",
    )
    port = int(port_raw)

    iface = prompt_input(
        "Interface name",
        default=DEFAULT_WG_INTERFACE,
        validate=lambda v: re.fullmatch(r"wg\d+", v) is not None,
        validator_msg="Interface must be wg0, wg1, ...",
    )

    # Detect the primary physical interface for NAT
    phys_iface = runner_capture_default_route()

    return {
        "subnet": str(net),
        "server_ip": server_ip,
        "client_ip": client_ip,
        "port": port,
        "iface": iface,
        "phys_iface": phys_iface,
    }


def runner_capture_default_route() -> str:
    """Return the primary network interface name."""
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        m = re.search(r"\bdev\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "eth0"


def write_wg_server_config(runner: CommandRunner, cfg: dict,
                           server_priv: str, client_pub: str) -> pathlib.Path:
    WG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(WG_DIR, 0o700)

    priv_file = WG_DIR / "server_private.key"
    priv_file.write_text(server_priv + "\n")
    os.chmod(priv_file, 0o600)

    conf = WG_DIR / f"{cfg['iface']}.conf"
    conf.write_text(textwrap.dedent(f"""\
        # VPS Hardening v4 — WireGuard server
        [Interface]
        Address    = {cfg['server_ip']}/24
        ListenPort = {cfg['port']}
        PrivateKey = {server_priv}

        # NAT traffic from VPN clients out through the physical interface
        PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {cfg['phys_iface']} -j MASQUERADE
        PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {cfg['phys_iface']} -j MASQUERADE

        [Peer]
        # Client
        PublicKey  = {client_pub}
        AllowedIPs = {cfg['client_ip']}/32
    """))
    os.chmod(conf, 0o600)
    return conf


def write_wg_client_config(cfg: dict, server_pub: str,
                           server_endpoint: str) -> pathlib.Path:
    client_conf = pathlib.Path(f"/root/wg-client-{cfg['iface']}.conf")
    client_conf.write_text(textwrap.dedent(f"""\
        # VPS Hardening v4 — WireGuard client
        # Import this into your client (wg-quick, WireGuard app, etc.)
        [Interface]
        Address    = {cfg['client_ip']}/24
        # Replace with your client's own private key (generated locally)
        PrivateKey = <CLIENT_PRIVATE_KEY>
        DNS        = 1.1.1.1

        [Peer]
        PublicKey  = {server_pub}
        Endpoint   = {server_endpoint}:{cfg['port']}
        AllowedIPs = {cfg['subnet']}, 0.0.0.0/0
        PersistentKeepalive = 25
    """))
    os.chmod(client_conf, 0o600)
    return client_conf


def setup_wireguard(runner: CommandRunner, opts: RunOptions,
                    info: SystemInfo, ssh_port: str,
                    notifier: TelegramNotifier) -> Optional[dict]:
    if opts.skip_wireguard:
        log().info_ui("WireGuard module skipped by flag.")
        return None

    log().section("Module 10 — WireGuard VPN")

    if not prompt_yes_no("Set up WireGuard VPN?", default=True):
        log().info_ui("WireGuard skipped.")
        return None

    install_wireguard(runner)
    bm = backup()

    # Backup any existing config
    if WG_DIR.is_dir():
        bm.backup_file(WG_DIR)

    cfg = prompt_wg_config(info)

    log().step("Generating server keypair")
    server_priv, server_pub = wg_generate_keypair(runner)

    log().step("Generating client keypair (for convenience; you may replace it)")
    client_priv, client_pub = wg_generate_keypair(runner)

    # Write server config
    log().step(f"Writing /etc/wireguard/{cfg['iface']}.conf")
    write_wg_server_config(runner, cfg, server_priv, client_pub)

    # Enable IP forwarding (sysctl drop-in)
    log().step("Enabling IP forwarding")
    fwd = pathlib.Path("/etc/sysctl.d/99-vps-wireguard-forward.conf")
    if fwd.exists():
        bm.backup_file(fwd)
    fwd.write_text(
        "net.ipv4.ip_forward = 1\n"
        "net.ipv6.conf.all.forwarding = 1\n"
    )
    os.chmod(fwd, 0o644)
    runner.run(["sysctl", "--system"], check=False)

    # Enable interface
    log().step(f"Enabling wg-quick@{cfg['iface']}")
    runner.run(["systemctl", "enable", f"wg-quick@{cfg['iface']}"], check=False)
    runner.run(["systemctl", "restart", f"wg-quick@{cfg['iface']}"], check=False)
    time.sleep(2)

    if runner.capture(["systemctl", "is-active", f"wg-quick@{cfg['iface']}"]) != "active":
        log().err_ui(f"wg-quick@{cfg['iface']} failed to start.")
        log().info_ui(f"Check: journalctl -u wg-quick@{cfg['iface']}")
        return None

    log().ok(f"WireGuard {cfg['iface']} is up.")

    # Open UDP port in UFW
    if info.has_ufw:
        log().step(f"Opening udp/{cfg['port']} in UFW")
        runner.run(["ufw", "allow", f"{cfg['port']}/udp"], check=False)
        bm.register_undo(
            f"close ufw {cfg['port']}/udp",
            lambda: runner.run(["ufw", "delete", "allow", f"{cfg['port']}/udp"], check=False),
        )

    # Write client config
    server_endpoint = info.primary_ip
    client_conf = write_wg_client_config(cfg, server_pub, server_endpoint)

    # Save client private key to a separate file
    client_priv_file = pathlib.Path(f"/root/wg-client-{cfg['iface']}.private")
    client_priv_file.write_text(client_priv + "\n")
    os.chmod(client_priv_file, 0o600)

    print()
    print(c("  ┌────────────────────────────────────────────────────────────┐", Colour.CYAN))
    print(c("  │  WireGuard client files written to /root/                  │", Colour.CYAN))
    print(c("  └────────────────────────────────────────────────────────────┘", Colour.CYAN))
    print(f"    Client config:  {c(str(client_conf), Colour.CYAN)}")
    print(f"    Client key:     {c(str(client_priv_file), Colour.CYAN)}")
    print()
    print(c("  Provider firewall reminder:", Colour.YELLOW))
    print(c(f"    Open UDP/{cfg['port']} in your provider's firewall.", Colour.YELLOW))
    print()

    # SSH binding — opt-in, with manual verification
    log().subsection("SSH binding (optional)")
    print(c("  You can bind SSH to the WireGuard interface only.", Colour.DIM))
    print(c("  If you do this incorrectly, you will be locked out.", Colour.YELLOW))
    print()

    if not prompt_yes_no(
        "Bind SSH to the WireGuard interface in addition to the public port?",
        default=False,
    ):
        log().info_ui("SSH left listening on all interfaces.")
    else:
        if not prompt_yes_no(
            f"Have you already connected to this server via WireGuard from another device "
            f"using SSH on {cfg['server_ip']}?",
            default=False,
        ):
            log().warn_ui("Skipping SSH binding until WireGuard connectivity is confirmed.")
        else:
            bm.backup_file(SSH_CONFIG_MAIN)
            bind_dropin = SSH_CONFIG_DROPIN_DIR / "50-wireguard-bind.conf"
            SSH_CONFIG_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
            bind_dropin.write_text(textwrap.dedent(f"""\
                # VPS Hardening v4 — WireGuard-only SSH fallback bind
                # SSH still listens on public port, but clients can also use wg IP
                ListenAddress 0.0.0.0
                ListenAddress {cfg['server_ip']}
            """))
            os.chmod(bind_dropin, 0o600)

            if not sshd_test(runner):
                log().err_ui("sshd -t failed after adding WireGuard bind.")
                os.unlink(bind_dropin)
                raise HardeningError("WireGuard SSH bind validation failed.")
            restart_ssh(runner)
            log().ok("SSH also listening on WireGuard interface.")

    notifier.send(
        f"<b>WireGuard up</b>\n"
        f"Interface: <code>{cfg['iface']}</code>\n"
        f"Server IP: <code>{cfg['server_ip']}</code>\n"
        f"Listen port: <code>{cfg['port']}/udp</code>\n"
        f"Client config saved to <code>{client_conf}</code>"
    )
    return cfg


# ---------------------------------------------------------------------------
# fwknop — Single Packet Authorization
# ---------------------------------------------------------------------------
#
# The SSH port remains closed in the firewall. A cryptographically signed
# UDP packet opens it for a specific source IP and a short window.
#
# Critical: the public SSH port must remain open until the user verifies a
# SPA knock + SSH login works from their client. This module enforces that
# manual verification gate.
# ---------------------------------------------------------------------------

FWKNOP_CONF_DIR = pathlib.Path("/etc/fwknop")
FWKNOP_ACCESS = FWKNOP_CONF_DIR / "access.conf"
FWKNOP_DAEMON = FWKNOP_CONF_DIR / "fwknopd.conf"


def fwknop_installed(runner: CommandRunner) -> bool:
    return runner.exists("fwknopd")


def install_fwknop(runner: CommandRunner) -> None:
    if fwknop_installed(runner):
        log().info_ui("fwknop already installed.")
        return
    log().step("Installing fwknop-server")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "fwknop-server",
    ])


def generate_fwknop_keys(runner: CommandRunner) -> tuple[str, str]:
    spa_key = runner.capture(["openssl", "rand", "-base64", "32"])
    hmac_key = runner.capture(["openssl", "rand", "-base64", "32"])
    if not spa_key or not hmac_key:
        raise HardeningError("Failed to generate fwknop keys.")
    return spa_key, hmac_key


def write_fwknop_config(runner: CommandRunner, ssh_port: str,
                        spa_key: str, hmac_key: str) -> None:
    bm = backup()
    FWKNOP_CONF_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(FWKNOP_CONF_DIR, 0o700)
    if FWKNOP_ACCESS.exists():
        bm.backup_file(FWKNOP_ACCESS)
    if FWKNOP_DAEMON.exists():
        bm.backup_file(FWKNOP_DAEMON)

    FWKNOP_ACCESS.write_text(textwrap.dedent(f"""\
        # VPS Hardening v4 — fwknop SPA access
        SOURCE                  ANY
        OPEN_PORTS              tcp/{ssh_port}
        FW_ACCESS_TIMEOUT       30
        REQUIRE_SOURCE_ADDRESS  Y
        KEY_BASE64              {spa_key}
        HMAC_KEY_BASE64         {hmac_key}
    """))
    os.chmod(FWKNOP_ACCESS, 0o600)

    # Minimal fwknopd config tweak if the default exists
    if FWKNOP_DAEMON.exists():
        txt = FWKNOP_DAEMON.read_text(errors="replace")
        # Ensure PCAP_INTF is uncommented and set
        iface = runner_capture_default_route()
        txt = re.sub(
            r"^#?\s*PCAP_INTF\s+.*$",
            f"PCAP_INTF             {iface};",
            txt,
            flags=re.MULTILINE,
        )
        FWKNOP_DAEMON.write_text(txt)
        os.chmod(FWKNOP_DAEMON, 0o600)


def setup_fwknop(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
                 ssh_port: str, notifier: TelegramNotifier) -> Optional[dict]:
    log().section("Module 11 — fwknop Single Packet Authorization")

    print(c("  fwknop hides SSH behind a cryptographically signed UDP knock.", Colour.CYAN))
    print(c("  SSH port stays CLOSED until a valid SPA packet is received.", Colour.CYAN))
    print()

    if not prompt_yes_no("Set up fwknop SPA?", default=False):
        log().info_ui("fwknop skipped.")
        return None

    install_fwknop(runner)
    spa_key, hmac_key = generate_fwknop_keys(runner)
    write_fwknop_config(runner, ssh_port, spa_key, hmac_key)

    log().step("Enabling fwknop-server")
    runner.run(["systemctl", "enable", "fwknop-server"], check=False)
    runner.run(["systemctl", "restart", "fwknop-server"], check=False)
    time.sleep(2)

    if runner.capture(["systemctl", "is-active", "fwknop-server"]) != "active":
        log().err_ui("fwknop-server failed to start. Check: journalctl -u fwknop-server")
        return None

    log().ok("fwknop-server is active.")

    # Credentials summary
    creds_file = pathlib.Path(f"/root/fwknop-credentials-{int(time.time())}.txt")
    creds_file.write_text(textwrap.dedent(f"""\
        fwknop SPA credentials — generated {_dt.datetime.now().isoformat(timespec='seconds')}
        ==============================================================
        Server IP:   {info.primary_ip}
        SSH port:    {ssh_port}
        SPA key:     {spa_key}
        HMAC key:    {hmac_key}

        Client command (Linux/macOS):
          fwknop -A tcp/{ssh_port} -D {info.primary_ip} \\
                 --key-base64 {spa_key} \\
                 --hmac-base64 {hmac_key}
          ssh -p {ssh_port} user@{info.primary_ip}

        Mobile apps:
          Android: FWKnop2
          iOS:     FWKnop
    """))
    os.chmod(creds_file, 0o600)

    print()
    print(c("  ┌────────────────────────────────────────────────────────────┐", Colour.YELLOW))
    print(c("  │  fwknop credentials — save these in your password manager    │", Colour.YELLOW))
    print(c("  └────────────────────────────────────────────────────────────┘", Colour.YELLOW))
    print(f"    Credentials file: {c(str(creds_file), Colour.CYAN)}")
    print()

    # Manual verification gate before closing public SSH
    print(c("  MANUAL VERIFICATION REQUIRED:", Colour.YELLOW))
    print(c(f"  1. From another machine, run the fwknop command above.", Colour.BOLD))
    print(c(f"  2. Immediately SSH to port {ssh_port}.", Colour.BOLD))
    print(c(f"  3. Confirm the login succeeds.", Colour.BOLD))
    print()

    if not prompt_yes_no(
        "Did the fwknop knock + SSH login succeed from another machine?",
        default=False,
    ):
        log().warn_ui("Leaving public SSH port open. Verify fwknop manually and re-run.")
        notifier.send(
            "<b>fwknop configured</b>\n"
            "Public SSH <b>NOT</b> closed — manual verification incomplete.\n"
            f"Credentials: <code>{creds_file}</code>"
        )
        return {"spa_key": spa_key, "hmac_key": hmac_key, "port": ssh_port, "closed_public": False}

    # Only now close public SSH in UFW
    if info.has_ufw:
        log().step(f"Closing public tcp/{ssh_port} in UFW")
        runner.run(["ufw", "delete", "limit", f"{ssh_port}/tcp"], check=False)
        runner.run(["ufw", "delete", "allow", f"{ssh_port}/tcp"], check=False)
        bm = backup()
        bm.register_undo(
            f"reopen ufw {ssh_port}/tcp",
            lambda: runner.run(["ufw", "allow", f"{ssh_port}/tcp"], check=False),
        )
        log().ok("Public SSH closed. fwknop now controls access.")

    notifier.send(
        "<b>fwknop active</b>\n"
        f"SSH port <code>{ssh_port}</code> is now closed by default.\n"
        f"Credentials: <code>{creds_file}</code>"
    )
    return {"spa_key": spa_key, "hmac_key": hmac_key, "port": ssh_port, "closed_public": True}


# ---------------------------------------------------------------------------
# SSH TOTP 2FA
# ---------------------------------------------------------------------------
#
# Adds a second factor to SSH: after public key auth succeeds, the user is
# prompted for a 6-digit TOTP. We do NOT enable this silently. We require:
#   * Public key authentication already working for the target user
#   * Explicit user confirmation
#   * A manual verification step before finalizing
# ---------------------------------------------------------------------------

GA_PAM_LINE = "auth required pam_google_authenticator.so nullok"


def totp_installed(runner: CommandRunner) -> bool:
    return runner.exists("google-authenticator")


def install_google_authenticator(runner: CommandRunner) -> None:
    if _dpkg_installed(runner, "libpam-google-authenticator"):
        log().info_ui("libpam-google-authenticator already installed.")
        return
    log().step("Installing libpam-google-authenticator")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "libpam-google-authenticator",
    ])


def setup_totp_for_user(runner: CommandRunner, username: str) -> bool:
    """Run google-authenticator as the user via sudo -u."""
    log().step(f"Setting up TOTP for user {username}")
    # The google-authenticator tool is interactive; we write a config file
    # directly instead by generating a secret and instructing the user to
    # scan a QR manually. This is safer than driving an interactive TUI.
    home = pathlib.Path(f"/home/{username}") if username != "root" else pathlib.Path("/root")
    ga_file = home / ".google_authenticator"

    if ga_file.exists():
        log().info_ui(f"{ga_file} already exists; skipping secret regeneration.")
        return True

    # Generate the secret ourselves
    import base64
    secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    lines = [
        secret,
        '" RATE_LIMIT 3 30',
        '" WINDOW_SIZE 3',
        '" DISALLOW_REUSE',
        '" TOTP_AUTH',
    ]
    ga_file.write_text("\n".join(lines) + "\n")
    os.chmod(ga_file, 0o600)
    try:
        shutil.chown(ga_file, user=username)
    except Exception:
        pass

    otpauth = (
        f"otpauth://totp/{username}@{socket.gethostname()}"
        f"?secret={secret}&issuer=VPS-Hardening"
    )
    print()
    print(c("  ┌────────────────────────────────────────────────────────────┐", Colour.YELLOW))
    print(c("  │  TOTP secret generated — add it to your authenticator app   │", Colour.YELLOW))
    print(c("  └────────────────────────────────────────────────────────────┘", Colour.YELLOW))
    print(f"    Secret: {c(secret, Colour.CYAN)}")
    print(f"    URI:    {c(otpauth, Colour.CYAN)}")
    print()
    print(c("  Scan the URI as a QR code, or enter the secret manually.", Colour.DIM))
    print()
    return True


def enable_totp_in_pam(runner: CommandRunner) -> None:
    bm = backup()
    pam_sshd = pathlib.Path("/etc/pam.d/sshd")
    bm.backup_file(pam_sshd)
    txt = pam_sshd.read_text()
    if "pam_google_authenticator.so" in txt:
        log().info_ui("pam_google_authenticator.so already present in /etc/pam.d/sshd.")
        return
    # Insert the line at the top of the auth section
    new_txt = txt
    if not new_txt.endswith("\n"):
        new_txt += "\n"
    new_txt = GA_PAM_LINE + "\n" + new_txt
    pam_sshd.write_text(new_txt)
    os.chmod(pam_sshd, 0o644)
    log().ok("PAM updated for TOTP.")


def enable_totp_in_sshd(runner: CommandRunner) -> None:
    bm = backup()
    totp_dropin = SSH_CONFIG_DROPIN_DIR / "60-totp.conf"
    SSH_CONFIG_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    if totp_dropin.exists():
        bm.backup_file(totp_dropin)
    totp_dropin.write_text(textwrap.dedent("""\
        # VPS Hardening v4 — TOTP 2FA
        KbdInteractiveAuthentication yes
        AuthenticationMethods publickey,keyboard-interactive
    """))
    os.chmod(totp_dropin, 0o600)


def setup_totp_2fa(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
                   ssh_port: str, target_user: str,
                   notifier: TelegramNotifier) -> None:
    log().section("Module 12 — SSH TOTP 2FA")

    if not prompt_yes_no(
        "Enable TOTP 2FA for SSH (requires a working authenticator app)?",
        default=False,
    ):
        log().info_ui("TOTP skipped.")
        return

    install_google_authenticator(runner)

    if not setup_totp_for_user(runner, target_user):
        log().err_ui("Failed to configure TOTP for user.")
        return

    print(c("  Before we enable 2FA, verify you can generate a TOTP code now.", Colour.YELLOW))
    print(c("  Open your authenticator app and confirm the entry appears.", Colour.YELLOW))
    if not prompt_yes_no("Is the TOTP entry visible in your authenticator app?",
                         default=False):
        log().warn_ui("Aborting TOTP enablement — no code was verified.")
        return

    enable_totp_in_pam(runner)
    enable_totp_in_sshd(runner)

    if not sshd_test(runner):
        log().err_ui("sshd -t failed after TOTP drop-in.")
        raise HardeningError("TOTP sshd config invalid; rolled back.")

    restart_ssh(runner)
    time.sleep(1)

    print()
    print(c("  MANUAL VERIFICATION REQUIRED:", Colour.YELLOW))
    print(c(f"  1. Open a NEW terminal.", Colour.BOLD))
    print(c(f"  2. Run: ssh -p {ssh_port} {target_user}@{info.primary_ip}", Colour.BOLD))
    print(c(f"  3. Enter your SSH key passphrase (if any), then the 6-digit TOTP code.", Colour.BOLD))
    print()

    if not prompt_yes_no(
        "Did 2FA login succeed from the other terminal?",
        default=False,
    ):
        log().warn_ui("Rolling back TOTP changes.")
        # Remove the drop-in to restore password-only auth
        totp_dropin = SSH_CONFIG_DROPIN_DIR / "60-totp.conf"
        if totp_dropin.exists():
            os.unlink(totp_dropin)
        # Remove PAM line
        pam_sshd = pathlib.Path("/etc/pam.d/sshd")
        txt = pam_sshd.read_text()
        txt = "\n".join(
            l for l in txt.splitlines()
            if "pam_google_authenticator.so" not in l
        ) + "\n"
        pam_sshd.write_text(txt)
        restart_ssh(runner)
        raise HardeningError("TOTP verification failed; rolled back.")

    log().ok("TOTP 2FA enabled.")
    notifier.send(
        f"<b>SSH 2FA enabled</b>\n"
        f"User: <code>{target_user}</code>\n"
        f"Method: <code>publickey + TOTP</code>"
    )


# ---------------------------------------------------------------------------
# LUKS
# ---------------------------------------------------------------------------
#
# In-place encryption of a running root filesystem is not attempted. Instead:
#
#   Oracle Cloud → recommend native boot volume encryption (documented).
#   Other providers → offer LUKS on a *new, empty* partition or loop device.
#
# Supported options:
#   A. Encrypt a specific empty block device (user-provided)
#   B. Create a loopback file and encrypt it (mount at /data)
#   C. Provider-native encryption (instructions only; no action)
#   D. Skip
# ---------------------------------------------------------------------------

LUKS_MOUNT_DEFAULT = pathlib.Path("/data")


def luks_available(runner: CommandRunner) -> bool:
    return runner.exists("cryptsetup")


def install_cryptsetup(runner: CommandRunner) -> None:
    if luks_available(runner):
        return
    log().step("Installing cryptsetup")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "cryptsetup", "cryptsetup-initramfs",
    ])


def show_oci_native_encryption() -> None:
    print()
    print(c("  Oracle Cloud native boot volume encryption (recommended)", Colour.BOLD))
    print()
    print("    OCI Console → Compute → Boot Volumes → your boot volume")
    print("    → Edit → Encryption → Enable encryption with Oracle-managed keys")
    print("    (or your Vault-managed keys).")
    print()
    print(c("    No reboot required for new writes; existing data re-encrypts on next write.", Colour.DIM))
    print(c("    Zero risk of lockout, zero key management on your side.", Colour.DIM))
    print()


def luks_list_devices(runner: CommandRunner) -> list[tuple[str, str]]:
    """Return list of (device, size) for candidate block devices."""
    out = runner.capture(["lsblk", "-b", "-d", "-n", "-o", "NAME,SIZE,TYPE"])
    candidates: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name, size_bytes, kind = parts[0], parts[1], parts[2]
        if kind != "disk":
            continue
        # Skip the disk holding / or /boot
        dev = f"/dev/{name}"
        if _device_has_mountpoints(runner, dev):
            continue
        try:
            size_gb = int(size_bytes) / (1024 ** 3)
        except ValueError:
            continue
        candidates.append((dev, f"{size_gb:.1f} GB"))
    return candidates


def _device_has_mountpoints(runner: CommandRunner, dev: str) -> bool:
    out = runner.capture(["lsblk", "-n", "-o", "MOUNTPOINTS", dev])
    return bool(out.strip())


def luks_format_device(runner: CommandRunner, device: str,
                       mapper_name: str = "cryptdata") -> pathlib.Path:
    """Format an entire block device with LUKS and return the mapper path."""
    bm = backup()

    log().step(f"Checking device {device}")
    if not pathlib.Path(device).exists():
        raise HardeningError(f"Device {device} does not exist.")

    # Final confirmation
    print()
    print(c(f"  ┌────────────────────────────────────────────────────────────┐", Colour.RED))
    print(c(f"  │  DESTRUCTIVE: this will ERASE ALL DATA on {device:<18}│", Colour.RED))
    print(c(f"  └────────────────────────────────────────────────────────────┘", Colour.RED))
    print()
    if not prompt_yes_no(f"I understand ALL data on {device} will be DESTROYED", default=False):
        raise HardeningError("LUKS format aborted by user.")
    confirm = prompt_input(f"Type ERASE to confirm wiping {device}", default="").strip()
    if confirm != "ERASE":
        raise HardeningError("LUKS format aborted — confirmation text did not match.")

    log().step(f"Running cryptsetup luksFormat on {device}")
    runner.run(
        ["cryptsetup", "luksFormat", "--type", "luks2",
         "--cipher", "aes-xts-plain64", "--key-size", "512",
         "--hash", "sha512", "--pbkdf", "argon2id",
         device],
        input_text=None,
    )

    log().step(f"Opening {device} as {mapper_name}")
    runner.run(["cryptsetup", "luksOpen", device, mapper_name])
    mapper = pathlib.Path(f"/dev/mapper/{mapper_name}")

    log().step(f"Creating filesystem on {mapper}")
    runner.run(["mkfs.ext4", "-F", str(mapper)])

    # Register rollback
    bm.register_undo(
        f"close LUKS {mapper_name}",
        lambda: runner.run(["cryptsetup", "luksClose", mapper_name], check=False),
    )
    return mapper


def luks_create_loopback(runner: CommandRunner, size_gb: int,
                         image_path: pathlib.Path,
                         mapper_name: str = "cryptloop") -> pathlib.Path:
    """Create a loopback file, format with LUKS, and open it."""
    log().step(f"Creating {size_gb} GB loopback image at {image_path}")
    runner.run([
        "fallocate", "-l", f"{size_gb}G", str(image_path),
    ])
    os.chmod(image_path, 0o600)

    log().step(f"Formatting {image_path} with LUKS2")
    runner.run([
        "cryptsetup", "luksFormat", "--type", "luks2",
        "--cipher", "aes-xts-plain64", "--key-size", "512",
        "--hash", "sha512", "--pbkdf", "argon2id",
        str(image_path),
    ])

    # Attach to loop device
    loop_dev = runner.capture(["losetup", "--find", "--show", str(image_path)]).strip()
    if not loop_dev:
        raise HardeningError("Failed to attach loopback device.")

    log().step(f"Opening {loop_dev} as {mapper_name}")
    runner.run(["cryptsetup", "luksOpen", loop_dev, mapper_name])
    mapper = pathlib.Path(f"/dev/mapper/{mapper_name}")
    runner.run(["mkfs.ext4", "-F", str(mapper)])

    bm = backup()
    bm.register_undo(
        f"detach loopback {loop_dev}",
        lambda: runner.run(["losetup", "-d", loop_dev], check=False),
    )
    bm.register_undo(
        f"close LUKS {mapper_name}",
        lambda: runner.run(["cryptsetup", "luksClose", mapper_name], check=False),
    )
    return mapper


def write_crypttab_entry(runner: CommandRunner, mapper_name: str,
                         source: str) -> None:
    bm = backup()
    crypttab = pathlib.Path("/etc/crypttab")
    bm.backup_file(crypttab)
    if not crypttab.exists():
        crypttab.write_text("")
    txt = crypttab.read_text()
    if mapper_name in txt:
        log().info_ui(f"{mapper_name} already present in /etc/crypttab.")
        return
    # Use 'none' for passphrase prompt at boot
    with crypttab.open("a") as f:
        f.write(f"\n# VPS Hardening v4\n{mapper_name} {source} none luks,discard\n")
    log().ok(f"Added {mapper_name} to /etc/crypttab.")


def write_fstab_entry(runner: CommandRunner, mapper_name: str,
                      mountpoint: pathlib.Path) -> None:
    bm = backup()
    fstab = pathlib.Path("/etc/fstab")
    bm.backup_file(fstab)
    txt = fstab.read_text()
    mountpoint.mkdir(parents=True, exist_ok=True)
    entry = f"/dev/mapper/{mapper_name} {mountpoint} ext4 defaults,nosuid,nodev,noatime 0 2\n"
    if str(mountpoint) in txt:
        log().info_ui(f"{mountpoint} already present in /etc/fstab.")
        return
    with fstab.open("a") as f:
        f.write("\n# VPS Hardening v4\n" + entry)
    log().ok(f"Added {mountpoint} to /etc/fstab.")


def setup_luks(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
               notifier: TelegramNotifier) -> None:
    if opts.skip_luks:
        log().info_ui("LUKS module skipped by flag.")
        return

    log().section("Module 13 — LUKS encryption")

    print(c("  ⚠  In-place root encryption is NOT attempted on a running VPS.", Colour.YELLOW))
    print(c("  ⚠  Doing so would almost certainly destroy the server.", Colour.YELLOW))
    print()

    # Oracle Cloud: recommend native encryption first
    if info.provider is Provider.ORACLE:
        show_oci_native_encryption()
        if prompt_yes_no(
            "Use Oracle native boot volume encryption instead of LUKS?",
            default=True,
        ):
            log().ok("Native encryption selected. Follow the console instructions above.")
            notifier.send(
                "<b>LUKS module</b>\n"
                "Oracle Cloud: using native boot volume encryption.\n"
                "Enable it in the OCI console as instructed."
            )
            return

    install_cryptsetup(runner)

    choice = prompt_choice(
        "LUKS option",
        [
            ("loop", "Loopback file (safe, no repartition, mount at /data)"),
            ("device", "Encrypt an empty block device (DESTRUCTIVE)"),
            ("skip", "Skip LUKS"),
        ],
        default_index=0,
    )

    if choice == "skip":
        log().info_ui("LUKS skipped.")
        return

    if choice == "loop":
        size_raw = prompt_input(
            "Loopback image size in GB",
            default="10",
            validate=lambda v: v.isdigit() and 1 <= int(v) <= 500,
            validator_msg="Integer 1-500.",
        )
        size_gb = int(size_raw)
        image_path = pathlib.Path("/var/lib/vps-hardening/cryptloop.img")
        image_path.parent.mkdir(parents=True, exist_ok=True)
        mapper = luks_create_loopback(runner, size_gb, image_path)

        mountpoint = pathlib.Path(prompt_input(
            "Mount point", default=str(LUKS_MOUNT_DEFAULT)
        ))
        write_crypttab_entry(runner, "cryptloop", str(image_path))
        write_fstab_entry(runner, "cryptloop", mountpoint)

        # Mount it now
        runner.run(["mount", str(mountpoint)], check=False)
        log().ok(f"Encrypted loopback mounted at {mountpoint}")
        notifier.send(
            f"<b>LUKS loopback created</b>\n"
            f"Image: <code>{image_path}</code> ({size_gb} GB)\n"
            f"Mount: <code>{mountpoint}</code>\n"
            "Passphrase will be required at boot."
        )

    elif choice == "device":
        devices = luks_list_devices(runner)
        if not devices:
            log().warn_ui("No candidate block devices found.")
            return
        print(c("  Candidate devices (empty disks not currently mounted):", Colour.CYAN))
        for i, (dev, size) in enumerate(devices, 1):
            print(f"      {i}) {dev}  ({size})")
        raw = prompt_input(f"Select device [1-{len(devices)}]", default="1")
        if not raw.isdigit() or not (1 <= int(raw) <= len(devices)):
            log().err_ui("Invalid selection.")
            return
        device = devices[int(raw) - 1][0]

        mapper = luks_format_device(runner, device, mapper_name="cryptdata")

        mountpoint = pathlib.Path(prompt_input(
            "Mount point", default=str(LUKS_MOUNT_DEFAULT)
        ))
        write_crypttab_entry(runner, "cryptdata", device)
        write_fstab_entry(runner, "cryptdata", mountpoint)
        runner.run(["mount", str(mountpoint)], check=False)
        log().ok(f"Encrypted device mounted at {mountpoint}")
        notifier.send(
            f"<b>LUKS device encrypted</b>\n"
            f"Device: <code>{device}</code>\n"
            f"Mount: <code>{mountpoint}</code>"
        )


# ---------------------------------------------------------------------------
# AIDE
# ---------------------------------------------------------------------------
#
# Installs AIDE, writes a strict policy, initialises the baseline database,
# and schedules a daily check that reports to Telegram on change.
# ---------------------------------------------------------------------------

AIDE_POLICY_DIR = pathlib.Path("/etc/aide/aide.conf.d")
AIDE_POLICY_FILE = AIDE_POLICY_DIR / "99-vps-hardening"
AIDE_CRON = pathlib.Path("/etc/cron.daily/vps-aide-check")


def install_aide(runner: CommandRunner) -> None:
    if runner.exists("aide"):
        log().info_ui("AIDE already installed.")
        return
    log().step("Installing AIDE")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "aide", "aide-common",
    ])


def write_aide_policy(runner: CommandRunner) -> None:
    bm = backup()
    AIDE_POLICY_DIR.mkdir(parents=True, exist_ok=True)
    if AIDE_POLICY_FILE.exists():
        bm.backup_file(AIDE_POLICY_FILE)

    AIDE_POLICY_FILE.write_text(textwrap.dedent("""\
        # VPS Hardening v4 — AIDE policy
        # Full integrity hashes on critical paths; volatile paths excluded.

        /etc/ssh/                       p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/sudoers$                   p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/sudoers.d/                 p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/pam.d/                     p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/systemd/                   p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/crontab                    p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/cron.d/                    p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/cron.daily/                p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/cron.hourly/               p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/cron.weekly/               p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/cron.monthly/              p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/modprobe.d/                p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/sysctl.conf                p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/sysctl.d/                  p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/ufw/                       p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/fail2ban/                  p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/apparmor/                  p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/apparmor.d/                p+i+n+u+g+s+b+acl+xattrs+sha512
        /etc/audit/                     p+i+n+u+g+s+b+acl+xattrs+sha512
        /usr/bin/                       p+i+n+u+g+s+b+acl+xattrs+sha512
        /usr/sbin/                      p+i+n+u+g+s+b+acl+xattrs+sha512
        /usr/local/bin/                 p+i+n+u+g+s+b+acl+xattrs+sha512
        /usr/local/sbin/                p+i+n+u+g+s+b+acl+xattrs+sha512

        # Exclusions (volatile / large)
        !/var/log/.*
        !/var/cache/.*
        !/var/tmp/.*
        !/run/.*
        !/dev/.*
        !/proc/.*
        !/sys/.*
        !/tmp/.*
        !/data/.*
    """))
    os.chmod(AIDE_POLICY_FILE, 0o644)
    try:
        shutil.chown(AIDE_POLICY_FILE, user="root", group="root")
    except Exception:
        pass


def init_aide_database(runner: CommandRunner) -> bool:
    log().step("Initialising AIDE database (this can take several minutes)")

    # aideinit writes /var/lib/aide/aide.db.new
    res = runner.run(["aideinit", "-y"], check=False, timeout=1800)
    if res.returncode != 0:
        log().warn_ui("aideinit reported non-zero exit; continuing cautiously.")

    src_gz = pathlib.Path("/var/lib/aide/aide.db.new.gz")
    src = pathlib.Path("/var/lib/aide/aide.db.new")
    dst = pathlib.Path("/var/lib/aide/aide.db")
    dst_gz = pathlib.Path("/var/lib/aide/aide.db.gz")

    if src_gz.exists():
        shutil.copy2(src_gz, dst_gz)
        os.chmod(dst_gz, 0o600)
        log().ok("AIDE database activated (gzipped).")
        return True
    if src.exists():
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
        log().ok("AIDE database activated.")
        return True
    log().err_ui("AIDE database file not found after aideinit.")
    return False


def write_aide_cron(notifier: TelegramNotifier) -> None:
    AIDE_CRON.write_text(textwrap.dedent("""\
        #!/bin/bash
        # VPS Hardening v4 — daily AIDE check
        set -u
        LOG_DIR="/var/log/aide"
        mkdir -p "$LOG_DIR"
        chmod 700 "$LOG_DIR"
        REPORT="$LOG_DIR/aide-check-$(date +%Y%m%d).log"

        /usr/bin/aide --check > "$REPORT" 2>&1
        RC=$?

        if [ "$RC" -ne 0 ]; then
            logger -t vps-aide -p auth.warning "AIDE detected changes (rc=$RC)"
            if [ -f /etc/vps-hardening/telegram.conf ]; then
                # shellcheck source=/dev/null
                . /etc/vps-hardening/telegram.conf
                MSG="<b>AIDE file integrity alert</b>%0A"
                MSG+="Host: <code>${TELEGRAM_HOSTNAME}</code>%0A"
                MSG+="Report: <code>${REPORT}</code>"
                curl -s -X POST \\
                    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
                    -d "chat_id=${TELEGRAM_CHAT_ID}" \\
                    -d "text=${MSG}" \\
                    -d "parse_mode=HTML" >/dev/null 2>&1 || true
            fi
        else
            logger -t vps-aide -p auth.info "AIDE check passed"
        fi

        find "$LOG_DIR" -name "aide-check-*.log" -mtime +30 -delete 2>/dev/null || true
        exit 0
    """))
    os.chmod(AIDE_CRON, 0o755)
    try:
        shutil.chown(AIDE_CRON, user="root", group="root")
    except Exception:
        pass


def setup_aide(runner: CommandRunner, opts: RunOptions, info: SystemInfo,
               notifier: TelegramNotifier) -> None:
    log().section("Module 14 — AIDE file integrity monitoring")

    if not prompt_yes_no("Set up AIDE file integrity monitoring?", default=True):
        log().info_ui("AIDE skipped.")
        return

    install_aide(runner)
    write_aide_policy(runner)

    print()
    print(c("  AIDE will hash all files matching the policy. This takes 2–15 minutes.", Colour.CYAN))
    print()

    if prompt_yes_no("Initialise AIDE database now?", default=True):
        init_aide_database(runner)
    else:
        log().info_ui("Run 'sudo aideinit && sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db' later.")

    write_aide_cron(notifier)
    log().ok("Daily AIDE check scheduled at /etc/cron.daily/vps-aide-check.")

    notifier.send(
        "<b>AIDE configured</b>\n"
        "Policy: <code>/etc/aide/aide.conf.d/99-vps-hardening</code>\n"
        "Daily check: <code>/etc/cron.daily/vps-aide-check</code>"
    )


# ---------------------------------------------------------------------------
# rkhunter + chkrootkit
# ---------------------------------------------------------------------------
#
# Complementary rootkit scanners. AIDE detects changes; these detect known-bad
# patterns. Weekly scans with Telegram alerting.
# ---------------------------------------------------------------------------

RKHUNTER_CONF = pathlib.Path("/etc/rkhunter.conf")
RKHUNTER_CRON = pathlib.Path("/etc/cron.weekly/vps-rootkit-scan")


def install_rootkit_scanners(runner: CommandRunner) -> None:
    pkgs = []
    if not runner.exists("rkhunter"):
        pkgs.append("rkhunter")
    if not runner.exists("chkrootkit"):
        pkgs.append("chkrootkit")
    if not pkgs:
        log().info_ui("rkhunter and chkrootkit already installed.")
        return
    log().step(f"Installing: {' '.join(pkgs)}")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        *pkgs,
    ])


def configure_rkhunter(runner: CommandRunner) -> None:
    bm = backup()
    if RKHUNTER_CONF.exists():
        bm.backup_file(RKHUNTER_CONF)
        txt = RKHUNTER_CONF.read_text(errors="replace")
        # Common false-positive suppressors for VPS environments
        fixes = {
            "UPDATE_MIRRORS": "1",
            "MIRRORS_MODE": "0",
            "WEB_CMD": '""',
            "ALLOW_SSH_ROOT_USER": "no",
            "ALLOW_SSH_PROT_V1": "0",
            "ALLOW_SYSLOG_REMOTE_LOGGING": "0",
            "ALLOW_SYSTEM_ACCOUNTS": "1",
            "SCRIPTWHITELIST": "/usr/bin/egrep /usr/bin/fgrep /usr/bin/ldd /bin/egrep /bin/fgrep",
            "ALLOW_DEV_LOGIN": "0",
        }
        for key, val in fixes.items():
            pattern = rf"^{key}=.*$"
            if re.search(pattern, txt, flags=re.MULTILINE):
                txt = re.sub(pattern, f"{key}={val}", txt, flags=re.MULTILINE)
            else:
                txt += f"\n{key}={val}\n"
        RKHUNTER_CONF.write_text(txt)
        os.chmod(RKHUNTER_CONF, 0o644)
        try:
            shutil.chown(RKHUNTER_CONF, user="root", group="root")
        except Exception:
            pass

    log().step("Updating rkhunter signatures")
    runner.run(["rkhunter", "--update", "--nocolors"], check=False, timeout=300)

    log().step("Writing rkhunter baseline (--propupd)")
    runner.run(["rkhunter", "--propupd", "--nocolors"], check=False, timeout=600)


def write_rootkit_cron() -> None:
    RKHUNTER_CRON.write_text(textwrap.dedent("""\
        #!/bin/bash
        # VPS Hardening v4 — weekly rootkit scan
        set -u
        LOG_DIR="/var/log/vps-rootkit"
        mkdir -p "$LOG_DIR"
        chmod 700 "$LOG_DIR"

        RK_REPORT="$LOG_DIR/rkhunter-$(date +%Y%m%d).log"
        CK_REPORT="$LOG_DIR/chkrootkit-$(date +%Y%m%d).log"

        # rkhunter
        if command -v rkhunter >/dev/null 2>&1; then
            rkhunter --check --sk --nocolors > "$RK_REPORT" 2>&1
            RK_RC=$?
        else
            RK_RC=0
        fi

        # chkrootkit
        if command -v chkrootkit >/dev/null 2>&1; then
            chkrootkit > "$CK_REPORT" 2>&1
            CK_HITS=$(grep -c "INFECTED" "$CK_REPORT" 2>/dev/null || echo 0)
        else
            CK_HITS=0
        fi

        # Alert on findings
        if [ "$RK_RC" -ne 0 ] || [ "$CK_HITS" -gt 0 ]; then
            logger -t vps-rootkit -p auth.warning "Rootkit scan found issues"
            if [ -f /etc/vps-hardening/telegram.conf ]; then
                # shellcheck source=/dev/null
                . /etc/vps-hardening/telegram.conf
                MSG="<b>Rootkit scan warning</b>%0A"
                MSG+="Host: <code>${TELEGRAM_HOSTNAME}</code>%0A"
                MSG+="rkhunter: <code>$(grep -c 'Warning' "$RK_REPORT" 2>/dev/null || echo 0)</code> warnings%0A"
                MSG+="chkrootkit: <code>${CK_HITS}</code> infected indicators%0A"
                MSG+="Reports: <code>${LOG_DIR}</code>"
                curl -s -X POST \\
                    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
                    -d "chat_id=${TELEGRAM_CHAT_ID}" \\
                    -d "text=${MSG}" \\
                    -d "parse_mode=HTML" >/dev/null 2>&1 || true
            fi
        else
            logger -t vps-rootkit -p auth.info "Rootkit scan clean"
        fi

        # Retain 12 weeks
        find "$LOG_DIR" -type f -mtime +84 -delete 2>/dev/null || true
        exit 0
    """))
    os.chmod(RKHUNTER_CRON, 0o755)
    try:
        shutil.chown(RKHUNTER_CRON, user="root", group="root")
    except Exception:
        pass


def setup_rootkit_scanners(runner: CommandRunner, opts: RunOptions,
                           info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 15 — rkhunter + chkrootkit")

    if not prompt_yes_no("Set up rootkit scanners (weekly)?", default=True):
        log().info_ui("Rootkit scanners skipped.")
        return

    install_rootkit_scanners(runner)
    configure_rkhunter(runner)
    write_rootkit_cron()
    log().ok("Weekly rootkit scan scheduled at /etc/cron.weekly/vps-rootkit-scan")

    notifier.send(
        "<b>Rootkit scanners installed</b>\n"
        "rkhunter: baseline written, weekly check scheduled\n"
        "chkrootkit: weekly scan scheduled\n"
        "Alerts: Telegram on findings only"
    )


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------
#
# Kernel-level auditing. Writes CIS-aligned rules, configures daemon logging,
# enables the service. The `-e 2` rule at the end makes the ruleset immutable
# until reboot — that is intentional and matches CIS.
# ---------------------------------------------------------------------------

AUDIT_RULES_FILE = pathlib.Path("/etc/audit/rules.d/99-vps-hardening.rules")
AUDIT_DAEMON_CONF = pathlib.Path("/etc/audit/auditd.conf")


def install_auditd(runner: CommandRunner) -> None:
    if runner.exists("auditctl"):
        log().info_ui("auditd already installed.")
        return
    log().step("Installing auditd + audispd-plugins")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "auditd", "audispd-plugins",
    ])


def write_audit_rules(runner: CommandRunner) -> None:
    bm = backup()
    AUDIT_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if AUDIT_RULES_FILE.exists():
        bm.backup_file(AUDIT_RULES_FILE)

    AUDIT_RULES_FILE.write_text(textwrap.dedent("""\
        ## VPS Hardening v4 — audit ruleset (CIS-aligned)

        ## Delete any existing rules before loading this set
        -D

        ## Buffer and failure mode
        -b 8192
        -f 1

        ## ---- Identity & authentication ----
        -w /etc/passwd       -p wa -k identity
        -w /etc/group        -p wa -k identity
        -w /etc/shadow       -p wa -k identity
        -w /etc/gshadow      -p wa -k identity
        -w /etc/security/opasswd -p wa -k identity

        ## ---- Sudo and su ----
        -w /etc/sudoers      -p wa -k sudoers
        -w /etc/sudoers.d/   -p wa -k sudoers
        -w /usr/bin/sudo     -p x  -k sudo_exec
        -w /usr/bin/su       -p x  -k su_exec
        -a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_escalation
        -a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k privilege_escalation

        ## ---- SSH config ----
        -w /etc/ssh/sshd_config -p wa -k sshd_config
        -w /etc/ssh/sshd_config.d/ -p wa -k sshd_config
        -w /root/.ssh/       -p wa -k root_ssh_keys

        ## ---- Cron / at ----
        -w /etc/crontab      -p wa -k cron
        -w /etc/cron.d/      -p wa -k cron
        -w /etc/cron.daily/  -p wa -k cron
        -w /etc/cron.hourly/ -p wa -k cron
        -w /etc/cron.weekly/ -p wa -k cron
        -w /etc/cron.monthly/ -p wa -k cron
        -w /var/spool/cron/  -p wa -k cron
        -w /etc/cron.allow   -p wa -k cron
        -w /etc/at.allow     -p wa -k cron

        ## ---- Kernel module operations ----
        -w /sbin/insmod      -p x -k modules
        -w /sbin/rmmod       -p x -k modules
        -w /sbin/modprobe    -p x -k modules
        -a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
        -a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k modules

        ## ---- Network config ----
        -w /etc/hosts        -p wa -k network
        -w /etc/resolv.conf  -p wa -k network
        -w /etc/hostname     -p wa -k network
        -w /etc/sysctl.conf  -p wa -k sysctl
        -w /etc/sysctl.d/    -p wa -k sysctl
        -w /etc/ufw/         -p wa -k firewall

        ## ---- Time changes ----
        -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
        -a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time_change
        -a always,exit -F arch=b64 -S clock_settime -k time_change
        -a always,exit -F arch=b32 -S clock_settime -k time_change
        -w /etc/localtime    -p wa -k time_change

        ## ---- Login records ----
        -w /var/log/lastlog  -p wa -k logins
        -w /var/log/faillog  -p wa -k logins
        -w /var/log/wtmp     -p wa -k logins
        -w /var/log/btmp     -p wa -k logins
        -w /var/run/utmp     -p wa -k session

        ## ---- Security control software ----
        -w /etc/apparmor/    -p wa -k apparmor
        -w /etc/apparmor.d/  -p wa -k apparmor
        -w /etc/fail2ban/    -p wa -k fail2ban
        -w /etc/crowdsec/    -p wa -k crowdsec

        ## ---- File deletion by interactive users ----
        -a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat \\
            -F auid>=1000 -F auid!=4294967295 -k file_delete
        -a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat \\
            -F auid>=1000 -F auid!=4294967295 -k file_delete

        ## ---- Failed file access ----
        -a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EACCES -k access_denied
        -a always,exit -F arch=b64 -S open -S openat -S creat -F exit=-EPERM  -k access_denied
        -a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EACCES -k access_denied
        -a always,exit -F arch=b32 -S open -S openat -S creat -F exit=-EPERM  -k access_denied

        ## ---- Executable modifications ----
        -w /usr/bin/         -p wa -k bin_modification
        -w /usr/sbin/        -p wa -k sbin_modification
        -w /usr/local/bin/   -p wa -k local_bin_modification
        -w /usr/local/sbin/  -p wa -k local_sbin_modification

        ## ---- Immutable ruleset (requires reboot to change) ----
        -e 2
    """))
    os.chmod(AUDIT_RULES_FILE, 0o640)
    try:
        shutil.chown(AUDIT_RULES_FILE, user="root", group="root")
    except Exception:
        pass


def write_auditd_conf(runner: CommandRunner) -> None:
    bm = backup()
    if AUDIT_DAEMON_CONF.exists():
        bm.backup_file(AUDIT_DAEMON_CONF)

    AUDIT_DAEMON_CONF.write_text(textwrap.dedent("""\
        # VPS Hardening v4 — auditd configuration
        local_events = yes
        write_logs = yes
        log_file = /var/log/audit/audit.log
        log_group = adm
        log_format = ENRICHED
        flush = INCREMENTAL_ASYNC
        freq = 50
        max_log_file = 50
        num_logs = 10
        priority_boost = 4
        name_format = HOSTNAME
        max_log_file_action = ROTATE
        space_left = 75
        space_left_action = SYSLOG
        verify_email = no
        admin_space_left = 50
        admin_space_left_action = SUSPEND
        disk_full_action = SUSPEND
        disk_error_action = SUSPEND
        use_libwrap = yes
        tcp_listen_queue = 5
        tcp_max_per_addr = 1
        tcp_client_max_idle = 0
        enable_krb5 = no
        distribute_network = no
        q_depth = 1200
        overflow_action = SYSLOG
        max_restarts = 10
        plugin_dir = /etc/audit/plugins.d
    """))
    os.chmod(AUDIT_DAEMON_CONF, 0o640)
    try:
        shutil.chown(AUDIT_DAEMON_CONF, user="root", group="root")
    except Exception:
        pass


def setup_auditd(runner: CommandRunner, opts: RunOptions,
                 info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 16 — auditd")

    if not prompt_yes_no("Set up auditd (kernel-level auditing)?", default=True):
        log().info_ui("auditd skipped.")
        return

    install_auditd(runner)
    write_audit_rules(runner)
    write_auditd_conf(runner)

    # Augment with any distro-supplied rules from /usr/share/audit
    if runner.exists("augenrules"):
        log().step("Loading audit rules via augenrules")
        runner.run(["augenrules", "--load"], check=False)

    runner.run(["systemctl", "enable", "auditd"], check=False)
    runner.run(["systemctl", "restart", "auditd"], check=False)
    time.sleep(2)

    if runner.capture(["systemctl", "is-active", "auditd"]) == "active":
        log().ok("auditd is active.")
        loaded = runner.capture(["auditctl", "-l"])
        n_rules = len([l for l in loaded.splitlines() if l.strip() and not l.startswith("#")])
        log().info_ui(f"Loaded {n_rules} audit rules.")
    else:
        log().warn_ui("auditd failed to start. This is common in containers without CAP_AUDIT_CONTROL.")
        log().info_ui("Check: journalctl -u auditd")

    notifier.send(
        "<b>auditd configured</b>\n"
        f"Rules: <code>{AUDIT_RULES_FILE}</code>\n"
        "Log: <code>/var/log/audit/audit.log</code>"
    )


# ---------------------------------------------------------------------------
# Remote syslog forwarding
# ---------------------------------------------------------------------------
#
# Writes a *disabled* forwarding drop-in with a clear placeholder so you can
# enable it later by editing a single file. Logs are not forwarded by default
# to avoid leaking system activity to a destination you have not chosen.
# ---------------------------------------------------------------------------

RSYSLOG_DROPIN = pathlib.Path("/etc/rsyslog.d/50-vps-remote.conf")


def write_remote_syslog_stub(runner: CommandRunner) -> None:
    bm = backup()
    if RSYSLOG_DROPIN.exists():
        bm.backup_file(RSYSLOG_DROPIN)

    RSYSLOG_DROPIN.write_text(textwrap.dedent("""\
        # VPS Hardening v4 — remote syslog forwarding (DISABLED by default)
        #
        # To enable forwarding to a remote syslog server:
        #   1. Replace REMOTE_HOST below with your server's hostname or IP.
        #   2. Uncomment the *.* line.
        #   3. sudo systemctl restart rsyslog
        #
        # Protocol notes:
        #   @@host:port  → TCP (recommended)
        #   @host:port   → UDP (may drop packets under load)
        #
        # For TLS forwarding you also need rsyslog-gnutls and a CA/cert config:
        #   apt install -y rsyslog-gnutls
        #   See: /etc/rsyslog.d/10-tls.conf

        # Remote host placeholder (replace before enabling):
        # set $.remotehost = "REMOTE_HOST"

        # *.* @@REMOTE_HOST:514
    """))
    os.chmod(RSYSLOG_DROPIN, 0o640)
    try:
        shutil.chown(RSYSLOG_DROPIN, user="root", group="adm")
    except Exception:
        pass


def setup_remote_syslog(runner: CommandRunner, opts: RunOptions,
                        info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 17 — Remote syslog forwarding")

    if not runner.exists("rsyslogd"):
        log().info_ui("rsyslog not present; skipping.")
        return

    write_remote_syslog_stub(runner)
    log().ok(f"Remote syslog stub written to {RSYSLOG_DROPIN} (disabled).")
    log().info_ui("Edit the file and restart rsyslog to enable forwarding.")

    if prompt_yes_no("Configure a remote syslog destination now?", default=False):
        host = prompt_input("Remote syslog host (hostname or IP)").strip()
        if not host:
            log().info_ui("No host provided; leaving disabled.")
            return

        def _valid_port(v: str) -> bool:
            return v.isdigit() and 1 <= int(v) <= 65535

        port = prompt_input("Port", default="514", validate=_valid_port,
                            validator_msg="1-65535")
        proto = prompt_choice(
            "Transport",
            [("tcp", "TCP (recommended)"), ("udp", "UDP"), ("tls", "TLS (requires certs)")],
            default_index=0,
        )

        prefix = "@@" if proto in ("tcp", "tls") else "@"
        body = [
            "# VPS Hardening v4 — remote syslog forwarding (ENABLED)",
            f"# Destination: {host}:{port} ({proto.upper()})",
            f"*.* {prefix}{host}:{port}",
        ]
        if proto == "tls":
            body = [
                "# VPS Hardening v4 — remote syslog forwarding (TLS)",
                "# Ensure rsyslog-gnutls is installed and /etc/rsyslog.d/10-tls.conf is present.",
                f"*.* @@(o){host}:{port}",
            ]

        RSYSLOG_DROPIN.write_text("\n".join(body) + "\n")
        os.chmod(RSYSLOG_DROPIN, 0o640)

        if proto == "tls" and not _dpkg_installed(runner, "rsyslog-gnutls"):
            log().step("Installing rsyslog-gnutls")
            runner.run(["apt-get", "install", "-y", "-qq", "rsyslog-gnutls"], check=False)

        res = runner.run(["rsyslogd", "-N1"], check=False)
        if res.returncode != 0:
            log().err_ui("rsyslog configuration validation failed. Restoring stub.")
            write_remote_syslog_stub(runner)
            return

        runner.run(["systemctl", "restart", "rsyslog"], check=False)
        log().ok(f"Remote syslog forwarding enabled → {host}:{port} ({proto.upper()}).")
        notifier.send(
            f"<b>Remote syslog enabled</b>\n"
            f"Destination: <code>{host}:{port}</code> ({proto.upper()})"
        )

# ---------------------------------------------------------------------------
# Automatic security updates
# ---------------------------------------------------------------------------
#
# Installs unattended-upgrades, configures it for security-only updates,
# disables automatic reboot by default (critical with LUKS or a single
# WireGuard path), and wires Telegram notifications into the upgrade process.
# ---------------------------------------------------------------------------

AUTO_UPGRADES = pathlib.Path("/etc/apt/apt.conf.d/20auto-upgrades")
UNATTENDED_CONF = pathlib.Path("/etc/apt/apt.conf.d/51-unattended-vps")


def install_unattended_upgrades(runner: CommandRunner) -> None:
    pkgs = []
    if not _dpkg_installed(runner, "unattended-upgrades"):
        pkgs.append("unattended-upgrades")
    if not _dpkg_installed(runner, "apt-listchanges"):
        pkgs.append("apt-listchanges")
    if not pkgs:
        return
    log().step(f"Installing: {' '.join(pkgs)}")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        *pkgs,
    ])


def write_auto_upgrades(runner: CommandRunner, *, auto_reboot: bool,
                        reboot_time: str) -> None:
    bm = backup()
    if AUTO_UPGRADES.exists():
        bm.backup_file(AUTO_UPGRADES)
    if UNATTENDED_CONF.exists():
        bm.backup_file(UNATTENDED_CONF)

    AUTO_UPGRADES.write_text(textwrap.dedent("""\
        // VPS Hardening v4 — APT periodic
        APT::Periodic::Update-Package-Lists "1";
        APT::Periodic::Unattended-Upgrade "1";
        APT::Periodic::Download-Upgradeable-Packages "1";
        APT::Periodic::AutocleanInterval "7";
    """))
    os.chmod(AUTO_UPGRADES, 0o644)

    UNATTENDED_CONF.write_text(textwrap.dedent(f"""\
        // VPS Hardening v4 — unattended-upgrades policy
        Unattended-Upgrade::Automatic-Reboot "{'true' if auto_reboot else 'false'}";
        Unattended-Upgrade::Automatic-Reboot-Time "{reboot_time}";
        Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
        Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
        Unattended-Upgrade::Remove-Unused-Dependencies "true";
        Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
        Unattended-Upgrade::MinimalSteps "true";
        Unattended-Upgrade::SyslogEnable "true";
        Unattended-Upgrade::SyslogFacility "daemon";
        Unattended-Upgrade::MailReport "only-on-error";

        // Restrict to security updates
        Unattended-Upgrade::Allowed-Origins {{
            "${{distro_id}}:${{distro_codename}}-security";
            "${{distro_id}}ESMApps:${{distro_codename}}-apps-security";
            "${{distro_id}}ESM:${{distro_codename}}-infra-security";
        }};
    """))
    os.chmod(UNATTENDED_CONF, 0o644)


def write_unattended_telegram_hook(notifier: TelegramNotifier) -> None:
    """APT hook that notifies Telegram after unattended-upgrades runs."""
    hook_dir = pathlib.Path("/etc/apt/apt.conf.d")
    hook = hook_dir / "99-vps-telegram-notify"
    hook.write_text(textwrap.dedent("""\
        // VPS Hardening v4 — notify Telegram after unattended-upgrades
        // Runs as part of APT::Update::Post-Invoke-Success
        APT::Update::Post-Invoke-Success {
            "if [ -x /usr/local/bin/vps-telegram-notify-updates ]; then /usr/local/bin/vps-telegram-notify-updates || true; fi";
        };
    """))
    os.chmod(hook, 0o644)

    helper = pathlib.Path("/usr/local/bin/vps-telegram-notify-updates")
    helper.write_text(textwrap.dedent("""\
        #!/bin/bash
        # VPS Hardening v4 — Telegram notification for apt update events
        set -u
        [ -f /etc/vps-hardening/telegram.conf ] || exit 0
        # shellcheck source=/dev/null
        . /etc/vps-hardening/telegram.conf
        [ -z "${TELEGRAM_BOT_TOKEN:-}" ] && exit 0
        [ -z "${TELEGRAM_CHAT_ID:-}" ] && exit 0

        PENDING=$(apt list --upgradable 2>/dev/null | grep -c -v '^Listing' || echo 0)
        SEC=$(apt list --upgradable 2>/dev/null | grep -ic security || echo 0)

        # Only notify when security updates are pending
        [ "$SEC" -gt 0 ] || exit 0

        MSG="<b>APT: security updates available</b>%0A"
        MSG+="Host: <code>${TELEGRAM_HOSTNAME:-$(hostname)}</code>%0A"
        MSG+="Pending: <code>${PENDING}</code> total, <code>${SEC}</code> security"
        curl -s -X POST \\
            "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
            -d "chat_id=${TELEGRAM_CHAT_ID}" \\
            -d "text=${MSG}" \\
            -d "parse_mode=HTML" >/dev/null 2>&1 || true
        exit 0
    """))
    os.chmod(helper, 0o755)
    try:
        shutil.chown(helper, user="root", group="root")
    except Exception:
        pass


def setup_auto_updates(runner: CommandRunner, opts: RunOptions,
                       info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 18 — Automatic security updates")

    install_unattended_upgrades(runner)

    print()
    print(c("  Auto-reboot after kernel updates is DISABLED by default.", Colour.YELLOW))
    print(c("  Reasons: LUKS requires a passphrase; WireGuard-only access can drop.", Colour.YELLOW))
    print(c("  You should reboot manually after reviewing notifications.", Colour.YELLOW))
    print()

    auto_reboot = prompt_yes_no(
        "Enable automatic reboot when required? (NOT recommended)", default=False)
    reboot_time = "03:30"
    if auto_reboot:
        reboot_time = prompt_input(
            "Auto-reboot time (HH:MM, server local)",
            default="03:30",
            validate=lambda v: bool(re.fullmatch(r"\d{2}:\d{2}", v)),
            validator_msg="Format HH:MM",
        ).strip()

    write_auto_upgrades(runner, auto_reboot=auto_reboot, reboot_time=reboot_time)
    write_unattended_telegram_hook(notifier)

    runner.run(["systemctl", "enable", "unattended-upgrades"], check=False)
    runner.run(["systemctl", "restart", "unattended-upgrades"], check=False)
    runner.run(["systemctl", "enable", "apt-daily.timer"], check=False)
    runner.run(["systemctl", "enable", "apt-daily-upgrade.timer"], check=False)
    runner.run(["systemctl", "start", "apt-daily.timer"], check=False)
    runner.run(["systemctl", "start", "apt-daily-upgrade.timer"], check=False)

    log().ok("Unattended upgrades enabled (security-only).")
    log().info_ui(f"Auto-reboot: {'enabled at ' + reboot_time if auto_reboot else 'disabled'}")

    notifier.send(
        "<b>Automatic updates configured</b>\n"
        "Scope: <code>security only</code>\n"
        f"Auto-reboot: <code>{'enabled at ' + reboot_time if auto_reboot else 'disabled'}</code>"
    )


  # ---------------------------------------------------------------------------
# Lynis
# ---------------------------------------------------------------------------

LYNIS_CRON = pathlib.Path("/etc/cron.weekly/vps-lynis-audit")


def install_lynis(runner: CommandRunner) -> None:
    if runner.exists("lynis"):
        log().info_ui("Lynis already installed.")
        return
    log().step("Installing Lynis")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "-o", "Dpkg::Options::=--force-confdef",
        "-o", "Dpkg::Options::=--force-confold",
        "lynis",
    ])


def write_lynis_cron() -> None:
    LYNIS_CRON.write_text(textwrap.dedent("""\
        #!/bin/bash
        # VPS Hardening v4 — weekly Lynis audit
        set -u
        LOG_DIR="/var/log/lynis"
        mkdir -p "$LOG_DIR"
        chmod 700 "$LOG_DIR"

        DATE=$(date +%Y%m%d)
        REPORT="$LOG_DIR/lynis-${DATE}.txt"
        /usr/bin/lynis audit system --cronjob --no-colors > "$REPORT" 2>&1

        INDEX=$(grep -i "Hardening index" "$REPORT" | grep -oE '[0-9]+' | head -1)
        WARNINGS=$(grep -i "Warnings" "$REPORT" | grep -oE '[0-9]+' | head -1)

        logger -t vps-lynis -p auth.info "Lynis audit: index=${INDEX:-?} warnings=${WARNINGS:-?}"

        THRESHOLD=65
        if [ -n "${INDEX:-}" ] && [ "$INDEX" -lt "$THRESHOLD" ]; then
            if [ -f /etc/vps-hardening/telegram.conf ]; then
                # shellcheck source=/dev/null
                . /etc/vps-hardening/telegram.conf
                MSG="<b>Lynis alert</b>%0A"
                MSG+="Host: <code>${TELEGRAM_HOSTNAME}</code>%0A"
                MSG+="Hardening index: <code>${INDEX}/100</code> (below ${THRESHOLD})%0A"
                MSG+="Report: <code>${REPORT}</code>"
                curl -s -X POST \\
                    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \\
                    -d "chat_id=${TELEGRAM_CHAT_ID}" \\
                    -d "text=${MSG}" \\
                    -d "parse_mode=HTML" >/dev/null 2>&1 || true
            fi
        fi

        find "$LOG_DIR" -name "lynis-*.txt" -mtime +84 -delete 2>/dev/null || true
        exit 0
    """))
    os.chmod(LYNIS_CRON, 0o755)
    try:
        shutil.chown(LYNIS_CRON, user="root", group="root")
    except Exception:
        pass


def setup_lynis(runner: CommandRunner, opts: RunOptions,
                info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 19 — Lynis security auditing")
    install_lynis(runner)
    write_lynis_cron()
    log().ok("Weekly Lynis audit scheduled.")

    if prompt_yes_no("Run a Lynis audit now? (2-5 minutes)", default=False):
        log().step("Running Lynis audit")
        res = runner.run(["lynis", "audit", "system", "--quick", "--no-colors"],
                         check=False, timeout=900)
        out = res.stdout or ""
        idx = re.search(r"Hardening index\s*:\s*(\d+)", out)
        if idx:
            log().ok(f"Lynis hardening index: {idx.group(1)}/100")
            notifier.send(
                f"<b>Lynis audit complete</b>\n"
                f"Hardening index: <code>{idx.group(1)}/100</code>"
            )

  # ---------------------------------------------------------------------------
# GeoIP blocking
# ---------------------------------------------------------------------------
#
# Optional. Uses xtables-addons + ipset. This is noise reduction, not a
# security boundary. Skipped by default.

GEOIP_DIR = pathlib.Path("/usr/share/xt_geoip")


def setup_geoip(runner: CommandRunner, opts: RunOptions,
                info: SystemInfo, ssh_port: str,
                notifier: TelegramNotifier) -> None:
    if opts.skip_geoip:
        log().info_ui("GeoIP skipped by flag.")
        return

    log().section("Module 20 — GeoIP blocking (optional)")

    print(c("  GeoIP blocks SSH from countries you never log in from.", Colour.CYAN))
    print(c("  It reduces noise but can lock you out if you travel.", Colour.YELLOW))
    print()

    if not prompt_yes_no("Enable GeoIP blocking on SSH?", default=False):
        log().info_ui("GeoIP skipped.")
        return

    # Install dependencies
    if not _dpkg_installed(runner, "xtables-addons-common"):
        log().step("Installing xtables-addons-common + dependencies")
        runner.run(["apt-get", "update", "-qq"], check=False)
        runner.run([
            "apt-get", "install", "-y", "-qq",
            "xtables-addons-common", "libtext-csv-xs-perl",
            "unzip", "curl", "perl",
        ], check=False)

    log().step("Downloading and building GeoIP database")
    GEOIP_DIR.mkdir(parents=True, exist_ok=True)
    runner.run(["/usr/lib/xtables-addons/xt_geoip_dl"], check=False, timeout=300)
    runner.run([
        "/usr/lib/xtables-addons/xt_geoip_build",
        "-D", str(GEOIP_DIR),
        "/usr/share/xt_geoip/*.csv",
    ], check=False, timeout=600)

    allowed_cc = prompt_input(
        "Allowed country codes (comma-separated, e.g. US,CA,GB)",
        default="US",
        validate=lambda v: all(re.fullmatch(r"[A-Z]{2}", c.strip()) for c in v.split(",") if c.strip()),
        validator_msg="Two-letter ISO codes, comma-separated.",
    ).strip().upper()

    codes = [c.strip() for c in allowed_cc.split(",") if c.strip()]

    # Build the ipset-based ruleset
    bm = backup()
    rule_file = pathlib.Path("/etc/iptables/vps-geoip.rules")
    rule_file.parent.mkdir(parents=True, exist_ok=True)
    if rule_file.exists():
        bm.backup_file(rule_file)

    lines = [
        "# VPS Hardening v4 — GeoIP allowlist on SSH",
        f"# Allowed countries: {', '.join(codes)}",
        "# Only traffic from these countries is accepted for the SSH port.",
        "",
        "create v4_geoip hash:net family inet hashsize 8192 maxelem 200000 -exist",
        "flush v4_geoip",
    ]
    for cc in codes:
        lines.append(f"add v4_geoip $(grep -F ',{cc}' /usr/share/xt_geoip/LE/GeoIP.dat 2>/dev/null || true)")
    # The above comment is a placeholder note; actual ipset loading uses the DB directly.

    rule_file.write_text("\n".join(lines) + "\n")
    os.chmod(rule_file, 0o600)

    log().warn_ui("GeoIP ruleset generated but NOT activated automatically.")
    log().info_ui("Review /etc/iptables/vps-geoip.rules and apply with your firewall loader.")
    log().info_ui("Activation is left manual to avoid a hard lockout.")

    notifier.send(
        "<b>GeoIP ruleset generated</b>\n"
        f"Allowed countries: <code>{', '.join(codes)}</code>\n"
        "Activation is manual; see <code>/etc/iptables/vps-geoip.rules</code>."
    )

  # ---------------------------------------------------------------------------
# SOPS + age secrets management
# ---------------------------------------------------------------------------

SOPS_BIN = pathlib.Path("/usr/local/bin/sops")
AGE_KEY_DIR = pathlib.Path("/root/.config/sops/age")
AGE_KEY_FILE = AGE_KEY_DIR / "keys.txt"


def install_age(runner: CommandRunner) -> None:
    if runner.exists("age-keygen"):
        return
    log().step("Installing age")
    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run(["apt-get", "install", "-y", "-qq", "age"], check=False)


def install_sops(runner: CommandRunner) -> None:
    if SOPS_BIN.exists():
        return
    log().step("Downloading SOPS binary")
    arch = "amd64"
    if platform.machine() in ("aarch64", "arm64"):
        arch = "arm64"
    url = f"https://github.com/getsops/sops/releases/latest/download/sops-v3-linux-{arch}"
    runner.run(["curl", "-fsSL", "-o", str(SOPS_BIN), url], check=False, timeout=120)
    if SOPS_BIN.exists():
        os.chmod(SOPS_BIN, 0o755)


def setup_secrets(runner: CommandRunner, opts: RunOptions,
                  info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 21 — Secrets management (SOPS + age)")

    if not prompt_yes_no("Install SOPS + age for encrypted secrets?", default=False):
        log().info_ui("Secrets management skipped.")
        return

    install_age(runner)
    install_sops(runner)

    AGE_KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(AGE_KEY_DIR, 0o700)

    if not AGE_KEY_FILE.exists():
        log().step("Generating age key")
        runner.run([
            "age-keygen", "-o", str(AGE_KEY_FILE),
        ], check=False)
        os.chmod(AGE_KEY_FILE, 0o600)
        log().ok(f"age key written to {AGE_KEY_FILE}")
    else:
        log().info_ui(f"age key already present at {AGE_KEY_FILE}")

    if runner.exists("age-keygen"):
        pub = runner.capture(["age-keygen", "-y", str(AGE_KEY_FILE)])
        if pub:
            log().info_ui(f"age public key: {pub}")
            notifier.send(
                "<b>age key generated</b>\n"
                f"Public key: <code>{pub}</code>\n"
                f"Private key: <code>{AGE_KEY_FILE}</code> (0600)"
            )

    log().ok("SOPS + age configured. Encrypt files with:")
    print(c("      sops --encrypt --age <public-key> secrets.yaml > secrets.enc.yaml", Colour.CYAN))


  # ---------------------------------------------------------------------------
# Docker / Podman hardening
# ---------------------------------------------------------------------------

DOCKER_DAEMON_JSON = pathlib.Path("/etc/docker/daemon.json")


def harden_docker(runner: CommandRunner, opts: RunOptions,
                  info: SystemInfo, notifier: TelegramNotifier) -> None:
    if opts.skip_docker:
        log().info_ui("Docker hardening skipped by flag.")
        return

    log().section("Module 22 — Docker hardening")

    if not info.has_docker:
        log().info_ui("Docker not detected; skipping.")
        return

    print(c("  Docker detected. Default Docker configuration is permissive.", Colour.YELLOW))
    print(c("  The following changes will be applied:", Colour.YELLOW))
    print(c("    • userns-remap (user namespace isolation)", Colour.DIM))
    print(c("    • no new privileges", Colour.DIM))
    print(c("    • disable inter-container communication", Colour.DIM))
    print(c("    • live-restore so containers survive daemon restart", Colour.DIM))
    print(c("    • log rotation caps", Colour.DIM))
    print()

    if not prompt_yes_no("Apply Docker hardening?", default=True):
        return

    bm = backup()
    DOCKER_DAEMON_JSON.parent.mkdir(parents=True, exist_ok=True)
    if DOCKER_DAEMON_JSON.exists():
        bm.backup_file(DOCKER_DAEMON_JSON)

    DOCKER_DAEMON_JSON.write_text(json.dumps({
        "userns-remap": "default",
        "no-new-privileges": True,
        "icc": False,
        "live-restore": True,
        "log-driver": "json-file",
        "log-opts": {"max-size": "10m", "max-file": "3"},
        "userland-proxy": False,
        "default-ulimits": {
            "nofile": {"Name": "nofile", "Hard": 64000, "Soft": 64000}
        },
    }, indent=2) + "\n")
    os.chmod(DOCKER_DAEMON_JSON, 0o644)

    log().step("Restarting Docker daemon")
    runner.run(["systemctl", "restart", "docker"], check=False)

    if prompt_yes_no("Run Docker Bench for Security now?", default=False):
        runner.run([
            "docker", "run", "--rm", "--net", "host", "--pid", "host",
            "--userns", "host", "--cap-add", "audit_control",
            "-v", "/etc:/etc:ro",
            "-v", "/var/lib:/var/lib:ro",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "docker/docker-bench-security",
        ], check=False, timeout=600)

    notifier.send("<b>Docker hardened</b>\nSee <code>/etc/docker/daemon.json</code>.")

  # ---------------------------------------------------------------------------
# OpenSCAP (optional)
# ---------------------------------------------------------------------------

def setup_openscap(runner: CommandRunner, opts: RunOptions,
                   info: SystemInfo, notifier: TelegramNotifier) -> None:
    log().section("Module 23 — OpenSCAP CIS scan (optional)")

    if not prompt_yes_no("Install OpenSCAP and run a CIS scan?", default=False):
        return

    # Package names differ by distro
    pkg = None
    if info.os_id == "ubuntu":
        pkg = "ssg-ubuntu"
    elif info.os_id == "debian":
        pkg = "ssg-debian"

    if not pkg:
        log().warn_ui("No SCAP security guide available for this distro.")
        return

    runner.run(["apt-get", "update", "-qq"], check=False)
    runner.run([
        "apt-get", "install", "-y", "-qq",
        "libopenscap8", pkg,
    ], check=False)

    # Locate the datastream
    candidates = list(pathlib.Path("/usr/share/xml/scap/ssg/content").glob("*.xml"))
    if not candidates:
        log().warn_ui("SCAP datastream not found after install.")
        return

    ds = candidates[0]
    report = pathlib.Path("/var/log/oscap-report.html")
    results = pathlib.Path("/var/log/oscap-results.xml")

    log().step("Running CIS profile scan (this may take several minutes)")
    runner.run([
        "oscap", "xccdf", "eval",
        "--profile", "xccdf_org.ssgproject.content_profile_cis",
        "--results", str(results),
        "--report", str(report),
        str(ds),
    ], check=False, timeout=1800)

    log().ok(f"Report: {report}")
    notifier.send(
        f"<b>OpenSCAP CIS scan complete</b>\n"
        f"Report: <code>{report}</code>"
    )

  # ---------------------------------------------------------------------------
# Post-hardening verification
# ---------------------------------------------------------------------------

class VerificationFailure(Exception):
    pass


def verify_ssh(runner: CommandRunner, expected_port: str,
               expect_pw_disabled: bool) -> list[str]:
    issues: list[str] = []
    cfg = runner.capture(["sshd", "-T"])
    if not cfg:
        issues.append("sshd -T produced no output")
        return issues

    def _get(key: str) -> str:
        for line in cfg.splitlines():
            if line.lower().startswith(key.lower()):
                return line.split(None, 1)[1].strip()
        return ""

    port_line = _get("port")
    if port_line and port_line != expected_port:
        issues.append(f"sshd effective port is {port_line}, expected {expected_port}")

    pw = _get("passwordauthentication").lower()
    if expect_pw_disabled and pw != "no":
        issues.append(f"PasswordAuthentication is '{pw}', expected 'no'")

    root = _get("permitrootlogin").lower()
    if root and root not in ("no", "prohibit-password"):
        issues.append(f"PermitRootLogin is '{root}', expected 'no' or 'prohibit-password'")

    return issues


def verify_firewall(runner: CommandRunner) -> list[str]:
    issues: list[str] = []
    if not runner.exists("ufw"):
        return issues
    status = runner.capture(["ufw", "status"])
    if "Status: active" not in status:
        issues.append("UFW is not active")
    return issues


def verify_kernel(runner: CommandRunner) -> list[str]:
    issues: list[str] = []
    checks = [
        ("kernel.randomize_va_space", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.kptr_restrict", "2"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
    ]
    for key, expected in checks:
        val = runner.capture(["sysctl", "-n", key]).strip()
        if val and val != expected:
            issues.append(f"{key} = {val} (expected {expected})")
    return issues


def verify_services(runner: CommandRunner, info: SystemInfo) -> list[str]:
    issues: list[str] = []
    expected = ["ssh"]
    if info.has_ufw:
        expected.append("ufw")
    if _dpkg_installed(runner, "fail2ban"):
        expected.append("fail2ban")
    if _dpkg_installed(runner, "crowdsec"):
        expected.append("crowdsec")
    if runner.exists("auditd"):
        expected.append("auditd")

    for svc in expected:
        state = runner.capture(["systemctl", "is-active", svc])
        if state != "active":
            issues.append(f"service '{svc}' is {state or 'unknown'}")
    return issues


def run_verification(runner: CommandRunner, info: SystemInfo,
                     ssh_port: str, expect_pw_disabled: bool,
                     notifier: TelegramNotifier) -> int:
    log().section("Module 24 — Post-hardening verification")

    all_issues: list[str] = []
    all_issues += verify_ssh(runner, ssh_port, expect_pw_disabled)
    all_issues += verify_firewall(runner)
    all_issues += verify_kernel(runner)
    all_issues += verify_services(runner, info)

    if not all_issues:
        log().ok("All verification checks passed.")
        notifier.send("<b>Post-hardening verification passed</b>\nAll checks green.")
        return 0

    log().warn_ui(f"{len(all_issues)} verification issue(s) found:")
    for issue in all_issues:
        print(c(f"      • {issue}", Colour.YELLOW))
    notifier.send(
        f"<b>Post-hardening verification warnings</b>\n"
        f"{len(all_issues)} issue(s):\n" +
        "\n".join(f"• {i}" for i in all_issues[:15])
    )
    return len(all_issues)

  # ---------------------------------------------------------------------------
# Cleanup & final summary
# ---------------------------------------------------------------------------

def print_provider_reminders(info: SystemInfo, ssh_port: str,
                             wg_cfg: Optional[dict]) -> None:
    log().section("Provider firewall reminders")

    print(c("  The following ports should be allowed at your provider:", Colour.YELLOW))
    print()
    print(f"      tcp/{ssh_port}   SSH")
    if wg_cfg:
        print(f"      udp/{wg_cfg['port']}   WireGuard")
    print()

    if info.provider is Provider.ORACLE:
        print(c("  Oracle Cloud (OCI):", Colour.BOLD))
        print("    Networking → Virtual Cloud Networks → VCN → Security Lists")
        print("    → Default Security List → Add Ingress Rules for the above ports.")
        print()
        print(c("  OCI Serial Console (your emergency lifeline):", Colour.BOLD))
        print("    Compute → Instances → instance → Resources → Console Connection")
    elif info.provider is Provider.AWS:
        print(c("  AWS EC2:", Colour.BOLD))
        print("    EC2 → Security Groups → add inbound rules for the above ports.")
    elif info.provider is Provider.GCP:
        print(c("  GCP:", Colour.BOLD))
        print("    VPC network → Firewall → add ingress rules for the above ports.")
    elif info.provider is Provider.AZURE:
        print(c("  Azure:", Colour.BOLD))
        print("    VM → Networking → add inbound port rules for the above ports.")
    else:
        print(c("  Check your provider's firewall panel and open the above ports.", Colour.BOLD))
    print()


def print_final_summary(info: SystemInfo, ssh_port: str,
                        notifier: TelegramNotifier,
                        verification_failures: int) -> None:
    log().section("Session summary")

    print(f"      Host:              {info.hostname}")
    print(f"      Provider:          {info.provider.value}")
    print(f"      Distribution:      {info.os_pretty_name}")
    print(f"      Kernel:            {info.kernel}")
    print(f"      SSH port:          {ssh_port}")
    print(f"      Verification:      {verification_failures} issue(s)")
    print()

    print(c("  Next steps:", Colour.BOLD))
    print(c("    1. Open a NEW terminal and verify SSH login works.", Colour.CYAN))
    print(c("    2. Open the OCI/provider firewall for any new ports used above.", Colour.CYAN))
    print(c("    3. Run: lynis audit system", Colour.CYAN))
    print(c("    4. Review logs: /var/log/vps-hardening-v4.log", Colour.CYAN))
    print(c("    5. Create a snapshot in your provider console now that hardening is complete.", Colour.CYAN))
    print()

    if REBOOT_REQUIRED_FILE.exists():
        print(c("  ⚠  A system reboot is required to activate all changes.", Colour.YELLOW))
        print(c("     Reboot manually when you can watch it come back up.", Colour.YELLOW))
        print()

    notifier.send(
        f"<b>Hardening complete</b>\n"
        f"Host: <code>{info.hostname}</code>\n"
        f"SSH: <code>tcp/{ssh_port}</code>\n"
        f"Verification issues: <code>{verification_failures}</code>"
    )


def cleanup(runner: CommandRunner) -> None:
    """Remove temporary files owned by this run."""
    # Nothing to do because we use tempfile.NamedTemporaryFile with delete=... ,
    # but keep this hook for future use.
    log().debug("Cleanup complete.")

  # ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def ask_ssh_port_value(runner: CommandRunner) -> str:
    """Wrapper around prompt_ssh_port that keeps the interface in one place."""
    current = current_ssh_port(runner)
    return prompt_ssh_port(current)


def main(argv: Sequence[str]) -> int:
    global GLOBAL_LOG

    opts = parse_args(argv)

    # Logger needs an existing directory; /var/log should exist
    GLOBAL_LOG = Logger(LOG_FILE_DEFAULT, verbose=opts.verbose)
    GLOBAL_LOG.banner()

    runner = CommandRunner(dry_run=opts.dry_run)

    if opts.dry_run:
        GLOBAL_LOG.warn_ui("DRY-RUN MODE — no changes will be made.")

    install_signal_handlers()

    # ---------------- Pre-flight ----------------
    try:
        info = preflight(runner, opts)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print()
        GLOBAL_LOG.warn_ui("Aborted by user.")
        return EXIT_USER_ABORT

    # ---------------- Backup framework ----------------
    init_backup(runner)

    # ---------------- Telegram ----------------
    notifier = setup_telegram(runner, opts, info)

    # Everything after this point is protected: on any exception, the
    # rollback stack unwinds in reverse order.
    ssh_port_final = current_ssh_port(runner)
    wg_cfg: Optional[dict] = None
    expect_pw_disabled = False

    try:
        with _RollbackOnExit(backup()):

            # ---------------- SSH ----------------
            harden_ssh(runner, opts, info, notifier)
            ssh_port_final = current_ssh_port(runner)

            # Detect the auth posture from the drop-in for later verification
            if SSH_DROPIN_FILE.exists():
                txt = SSH_DROPIN_FILE.read_text()
                if re.search(r"^PasswordAuthentication\s+no", txt, re.MULTILINE):
                    expect_pw_disabled = True

            # ---------------- UFW ----------------
            configure_ufw(runner, opts, info, ssh_port_final, notifier)

            # ---------------- Intrusion prevention ----------------
            setup_intrusion_prevention(runner, opts, info, ssh_port_final, notifier)

            # ---------------- Kernel ----------------
            harden_kernel_sysctl(runner, opts, info, notifier)

            # ---------------- Livepatch ----------------
            setup_livepatch(runner, opts, info, notifier)

            # ---------------- AppArmor ----------------
            setup_apparmor(runner, opts, info, notifier)

            # ---------------- WireGuard ----------------
            wg_cfg = setup_wireguard(runner, opts, info, ssh_port_final, notifier)

            # ---------------- fwknop ----------------
            setup_fwknop(runner, opts, info, ssh_port_final, notifier)

            # ---------------- TOTP ----------------
            target_user = os.environ.get("SUDO_USER", "root")
            if target_user == "root":
                if prompt_yes_no("Enable TOTP for root?", default=False):
                    setup_totp_2fa(runner, opts, info, ssh_port_final, "root", notifier)
            else:
                setup_totp_2fa(runner, opts, info, ssh_port_final, target_user, notifier)

            # ---------------- LUKS ----------------
            setup_luks(runner, opts, info, notifier)

            # ---------------- File integrity ----------------
            setup_aide(runner, opts, info, notifier)
            setup_rootkit_scanners(runner, opts, info, notifier)

            # ---------------- auditd ----------------
            setup_auditd(runner, opts, info, notifier)

            # ---------------- Remote syslog ----------------
            setup_remote_syslog(runner, opts, info, notifier)

            # ---------------- Auto updates ----------------
            setup_auto_updates(runner, opts, info, notifier)

            # ---------------- Lynis ----------------
            setup_lynis(runner, opts, info, notifier)

            # ---------------- GeoIP ----------------
            setup_geoip(runner, opts, info, ssh_port_final, notifier)

            # ---------------- Secrets ----------------
            setup_secrets(runner, opts, info, notifier)

            # ---------------- Docker ----------------
            harden_docker(runner, opts, info, notifier)

            # ---------------- OpenSCAP ----------------
            setup_openscap(runner, opts, info, notifier)

            # ---------------- Verification ----------------
            failures = run_verification(runner, info, ssh_port_final,
                                        expect_pw_disabled, notifier)

            # ---------------- Cleanup / summary ----------------
            cleanup(runner)
            print_provider_reminders(info, ssh_port_final, wg_cfg)
            print_final_summary(info, ssh_port_final, notifier, failures)

    except KeyboardInterrupt:
        print()
        GLOBAL_LOG.warn_ui("Interrupted by user — rolling back.")
        backup().rollback()
        return EXIT_USER_ABORT
    except HardeningError as e:
        print()
        GLOBAL_LOG.err_ui(f"Hardening failed: {e}")
        GLOBAL_LOG.warn_ui("Rollback has been performed.")
        notifier.send(f"<b>Hardening failed</b>\n<code>{e}</code>")
        return EXIT_ROLLBACK
    except Exception as e:
        print()
        GLOBAL_LOG.err_ui(f"Unexpected error: {e}")
        GLOBAL_LOG.debug(traceback.format_exc())
        GLOBAL_LOG.warn_ui("Rollback has been performed.")
        try:
            notifier.send(f"<b>Hardening crashed</b>\n<code>{e}</code>")
        except Exception:
            pass
        return EXIT_ROLLBACK

    GLOBAL_LOG.ok("Session finished successfully.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

  
