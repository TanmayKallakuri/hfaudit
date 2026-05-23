from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from hfaudit.sandbox.config import (
    MaliciousBehavior,
    SandboxConfig,
    SandboxResult,
    SyscallEvent,
)
from hfaudit.sandbox.loader_scripts import pickle_loader_script

logger = logging.getLogger(__name__)

_STRACE_LINE_RE = re.compile(
    r"\[pid\s+(\d+)\]\s+"
    r"(\d+\.\d+)\s+"
    r"(\w+)\((.*)\)\s*=\s*(.+)"
)

_ALLOWED_PYTHON_BINARIES = frozenset({
    "/usr/bin/python3",
    "/usr/bin/python",
    "/usr/local/bin/python3",
    "/usr/local/bin/python",
    "/usr/bin/python3.11",
    "/usr/local/bin/python3.11",
})

_WRITE_FLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT"})

_WORKSPACE_PREFIX = "/workspace"


class SandboxRunner:
    def __init__(self, config: SandboxConfig | None = None) -> None:
        self._config = config or SandboxConfig()

    @property
    def config(self) -> SandboxConfig:
        return self._config

    def is_available(self) -> bool:
        """Check if gVisor runtime and Docker are available on this system."""
        if shutil.which(self._config.runtime) is None:
            return False
        if shutil.which("docker") is None:
            return False
        try:
            result = subprocess.run(
                ["docker", "info", "--format", "{{.Runtimes}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return self._config.runtime in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def run(self, model_path: str, loader_script: str | None = None) -> SandboxResult:
        """Execute a model load in an isolated container with syscall tracing."""
        start = time.monotonic()
        resolved = Path(model_path).resolve()
        if not resolved.is_file():
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr=f"Model file not found: {model_path}",
                duration_ms=int((time.monotonic() - start) * 1000),
                was_killed=False,
            )

        if loader_script is None:
            loader_script = pickle_loader_script("/model/" + resolved.name)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="hfaudit_loader_"
        ) as f:
            f.write(loader_script)
            loader_path = f.name

        try:
            cmd = self._build_docker_cmd(str(resolved), loader_path)
            was_killed = False
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._config.wall_clock_timeout_s,
                )
                exit_code = proc.returncode
                stdout = proc.stdout
                stderr = proc.stderr
            except subprocess.TimeoutExpired as e:
                was_killed = True
                exit_code = -1
                stdout = e.stdout if isinstance(e.stdout, str) else (e.stdout or b"").decode(
                    errors="replace"
                )
                stderr = e.stderr if isinstance(e.stderr, str) else (e.stderr or b"").decode(
                    errors="replace"
                )

            syscalls = self._parse_strace_output(stderr) if self._config.strace_enabled else []
            behaviors = self._detect_malicious_behaviors(syscalls)
            duration_ms = int((time.monotonic() - start) * 1000)

            return SandboxResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                syscalls=syscalls,
                duration_ms=duration_ms,
                was_killed=was_killed,
                malicious_behaviors=behaviors,
            )
        finally:
            try:
                Path(loader_path).unlink(missing_ok=True)
            except OSError:
                pass

    def _build_docker_cmd(self, model_path: str, loader_script_path: str) -> list[str]:
        """Build the docker run command with all security constraints."""
        cfg = self._config
        container_model_dir = "/model"

        cmd = [
            "docker", "run", "--rm",
            f"--runtime={cfg.runtime}",
            f"--network={cfg.network}",
            f"--cpus={cfg.cpu_limit}",
            f"--memory={cfg.memory_limit_mb}m",
            "--security-opt=no-new-privileges",
        ]

        if cfg.read_only_root:
            cmd.append("--read-only")

        cmd.append(f"--tmpfs=/workspace:size={cfg.tmpfs_size_mb}m")

        parent_dir = str(Path(model_path).parent)
        cmd.extend(["-v", f"{parent_dir}:{container_model_dir}:ro"])
        cmd.extend(["-v", f"{loader_script_path}:/loader.py:ro"])

        if cfg.strace_enabled:
            cmd.extend([
                cfg.image,
                "strace", "-f", "-e", "trace=execve,clone,connect,open,openat,sendto",
                "-tt", "-o", "/dev/stderr",
                "python3", "/loader.py",
            ])
        else:
            cmd.extend([cfg.image, "python3", "/loader.py"])

        return cmd

    def _parse_strace_output(self, strace_output: str) -> list[SyscallEvent]:
        """Parse strace output into structured events."""
        events: list[SyscallEvent] = []
        for line in strace_output.splitlines():
            m = _STRACE_LINE_RE.match(line.strip())
            if m is None:
                continue
            pid_str, ts_str, syscall, raw_args, ret_str = m.groups()
            try:
                pid = int(pid_str)
            except ValueError:
                pid = 0

            try:
                ts_ms = int(float(ts_str) * 1000)
            except ValueError:
                ts_ms = 0

            ret_val = _parse_return_value(ret_str)
            args = _split_args(raw_args)

            events.append(SyscallEvent(
                timestamp_ms=ts_ms,
                syscall=syscall,
                args=args,
                return_value=ret_val,
                pid=pid,
            ))
        return events

    def _detect_malicious_behaviors(
        self, events: list[SyscallEvent]
    ) -> list[MaliciousBehavior]:
        """Analyze syscall events for known malicious patterns."""
        behaviors: list[MaliciousBehavior] = []
        for ev in events:
            if ev.syscall in ("execve", "clone"):
                behavior = _check_process_execution(ev)
                if behavior is not None:
                    behaviors.append(behavior)

            if ev.syscall == "connect":
                behavior = _check_network_connect(ev)
                if behavior is not None:
                    behaviors.append(behavior)
                behavior = _check_dns_query_connect(ev)
                if behavior is not None:
                    behaviors.append(behavior)

            if ev.syscall == "sendto":
                behavior = _check_dns_query_sendto(ev)
                if behavior is not None:
                    behaviors.append(behavior)

            if ev.syscall in ("open", "openat"):
                behavior = _check_filesystem_write(ev)
                if behavior is not None:
                    behaviors.append(behavior)

        return behaviors


def _parse_return_value(ret_str: str) -> int:
    """Extract the integer return value from strace output like '0' or '-1 ENETUNREACH'."""
    token = ret_str.strip().split()[0] if ret_str.strip() else "0"
    try:
        return int(token)
    except ValueError:
        return 0


def _split_args(raw: str) -> list[str]:
    """Split raw strace argument string into individual args."""
    if not raw.strip():
        return []
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    in_string = False
    escape = False
    for ch in raw:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            current.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            current.append(ch)
            continue
        if in_string:
            current.append(ch)
            continue
        if ch in ("{", "["):
            depth += 1
            current.append(ch)
            continue
        if ch in ("}", "]"):
            depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return parts


def _check_process_execution(ev: SyscallEvent) -> MaliciousBehavior | None:
    """Flag execve/clone calls that invoke binaries outside the Python interpreter."""
    if ev.syscall == "execve" and ev.args:
        binary = ev.args[0].strip('"')
        if binary not in _ALLOWED_PYTHON_BINARIES:
            return MaliciousBehavior(
                category="process_execution",
                description=f"Suspicious process execution: {binary}",
                evidence=f"execve({', '.join(ev.args)}) = {ev.return_value}",
                severity="critical",
            )
    return None


def _check_network_connect(ev: SyscallEvent) -> MaliciousBehavior | None:
    """Flag any connect() syscall — network is disabled so any attempt is suspicious."""
    if ev.syscall == "connect":
        if _is_dns_port(ev):
            return None
        return MaliciousBehavior(
            category="network_connect",
            description="Network connection attempt from sandboxed process",
            evidence=f"connect({', '.join(ev.args)}) = {ev.return_value}",
            severity="critical",
        )
    return None


def _check_dns_query_connect(ev: SyscallEvent) -> MaliciousBehavior | None:
    """Flag connect() to port 53 as DNS exfiltration attempt."""
    if ev.syscall == "connect" and _is_dns_port(ev):
        return MaliciousBehavior(
            category="dns_query",
            description="DNS query attempt from sandboxed process",
            evidence=f"connect({', '.join(ev.args)}) = {ev.return_value}",
            severity="high",
        )
    return None


def _check_dns_query_sendto(ev: SyscallEvent) -> MaliciousBehavior | None:
    """Flag sendto() with DNS-looking payloads."""
    if ev.syscall == "sendto":
        args_str = " ".join(ev.args)
        if "sin_port=htons(53)" in args_str or "port=53" in args_str.lower():
            return MaliciousBehavior(
                category="dns_query",
                description="DNS query via sendto from sandboxed process",
                evidence=f"sendto({', '.join(ev.args)}) = {ev.return_value}",
                severity="high",
            )
    return None


def _check_filesystem_write(ev: SyscallEvent) -> MaliciousBehavior | None:
    """Flag open/openat with write flags outside /workspace."""
    args_str = " ".join(ev.args)
    has_write_flag = any(flag in args_str for flag in _WRITE_FLAGS)
    if not has_write_flag:
        return None

    file_path = ""
    for arg in ev.args:
        stripped = arg.strip('"')
        if stripped.startswith("/"):
            file_path = stripped
            break

    if file_path.startswith(_WORKSPACE_PREFIX):
        return None

    return MaliciousBehavior(
        category="filesystem_write",
        description=f"Write attempt outside workspace: {file_path or 'unknown path'}",
        evidence=f"{ev.syscall}({', '.join(ev.args)}) = {ev.return_value}",
        severity="critical",
    )


def _is_dns_port(ev: SyscallEvent) -> bool:
    """Check if a connect event targets port 53."""
    args_str = " ".join(ev.args)
    return "sin_port=htons(53)" in args_str or "port=53" in args_str.lower()
