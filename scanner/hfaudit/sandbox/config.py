from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SyscallEvent:
    timestamp_ms: int
    syscall: str
    args: list[str] = field(default_factory=list)
    return_value: int = 0
    pid: int = 0


@dataclass(frozen=True)
class MaliciousBehavior:
    category: str
    description: str
    evidence: str
    severity: str


@dataclass(frozen=True)
class SandboxConfig:
    runtime: str = "runsc"
    network: str = "none"
    read_only_root: bool = True
    tmpfs_size_mb: int = 256
    cpu_limit: float = 1.0
    memory_limit_mb: int = 2048
    wall_clock_timeout_s: int = 120
    dns_sinkhole: bool = True
    image: str = "python:3.11-slim"
    strace_enabled: bool = True


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    syscalls: list[SyscallEvent] = field(default_factory=list)
    duration_ms: int = 0
    was_killed: bool = False
    malicious_behaviors: list[MaliciousBehavior] = field(default_factory=list)
