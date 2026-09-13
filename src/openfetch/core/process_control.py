"""Owned subprocess execution with bounded timeout and process-tree cleanup.

The downloader can run yt-dlp work in an isolated child process and send its
request over stdin.  On Windows each child is placed in a new process group;
cleanup targets only the validated PID owned by this supervisor and uses
``taskkill /PID <pid> /T`` before the bounded ``/F`` fallback.  POSIX uses a
new session and signals that process group instead.

An optional ownership record stores only PIDs, process creation identities,
and the executable path--never the command line or stdin payload.  A later
application instance can therefore recover a tree left by a crashed owner
without killing an unrelated process that reused the same PID.
"""

from __future__ import annotations

import codecs
import contextlib
import ctypes
import hashlib
import json
import os
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_INACTIVITY_TIMEOUT_SECONDS = 300.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 21_600.0
DEFAULT_STATUS_INTERVAL_SECONDS = 15.0
DEFAULT_TERMINATION_GRACE_SECONDS = 3.0
DEFAULT_FORCE_KILL_WAIT_SECONDS = 3.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.1
DEFAULT_PIPE_JOIN_TIMEOUT_SECONDS = 2.0
OWNERSHIP_RECORD_SCHEMA = 1

OutputCallback = Callable[[str], None]
StatusCallback = Callable[["ProcessStatus"], None]
CancelCallback = Callable[[], bool]


class ProcessOutcome(str, Enum):
    """Terminal outcome for one owned process attempt."""

    EXITED = "exited"
    CANCELLED = "cancelled"
    INACTIVITY_TIMEOUT = "inactivity_timeout"
    TOTAL_TIMEOUT = "total_timeout"


class ProcessPhase(str, Enum):
    """Low-frequency lifecycle status suitable for a GUI heartbeat."""

    STARTED = "started"
    ACTIVE = "active"
    CANCELLING = "cancelling"
    INACTIVITY_TIMEOUT = "inactivity_timeout"
    TOTAL_TIMEOUT = "total_timeout"
    EXITED = "exited"


class RecoveryState(str, Enum):
    """Result of checking a persisted ownership record."""

    NO_RECORD = "no_record"
    OWNER_ACTIVE = "owner_active"
    PROCESS_GONE = "process_gone"
    IDENTITY_MISMATCH = "identity_mismatch"
    TERMINATED = "terminated"
    INVALID_RECORD = "invalid_record"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ProcessLimits:
    """Timeout and cleanup limits for one child-process attempt."""

    inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT_SECONDS
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT_SECONDS
    status_interval: float = DEFAULT_STATUS_INTERVAL_SECONDS
    termination_grace: float = DEFAULT_TERMINATION_GRACE_SECONDS
    force_kill_wait: float = DEFAULT_FORCE_KILL_WAIT_SECONDS
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS
    pipe_join_timeout: float = DEFAULT_PIPE_JOIN_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        for name in (
            "inactivity_timeout",
            "total_timeout",
            "status_interval",
            "termination_grace",
            "force_kill_wait",
            "poll_interval",
            "pipe_join_timeout",
        ):
            value = getattr(self, name)
            if not isinstance(value, int | float) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive number")


@dataclass(frozen=True, slots=True)
class ProcessStatus:
    """A lifecycle transition or periodic active heartbeat."""

    pid: int
    phase: ProcessPhase
    elapsed_seconds: float
    inactive_seconds: float


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Captured result for a completed, cancelled, or timed-out attempt."""

    args: tuple[str, ...]
    pid: int | None
    returncode: int | None
    outcome: ProcessOutcome
    stdout: str
    stderr: str
    elapsed_seconds: float
    forced_kill: bool = False


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    """Safe stale-process recovery result."""

    state: RecoveryState
    pid: int | None = None
    detail: str = ""


class ProcessControlError(RuntimeError):
    """Base class for supervised-process failures with captured diagnostics."""

    def __init__(self, message: str, result: ProcessResult) -> None:
        self.result = result
        super().__init__(message)


class ProcessCancelledError(ProcessControlError):
    """Raised after explicit cancellation and bounded tree cleanup."""


class ProcessInactivityTimeoutError(ProcessControlError):
    """Raised when no meaningful stdout/stderr arrives within the limit."""


class ProcessTotalTimeoutError(ProcessControlError):
    """Raised when the attempt exceeds its maximum total duration."""


class ProcessLaunchError(RuntimeError):
    """Raised when an owned process cannot be launched or recorded safely."""


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    token: str
    executable: str


@dataclass(frozen=True, slots=True)
class _OwnershipRecord:
    pid: int
    owner_pid: int
    process_identity: str
    owner_identity: str
    executable: str
    process_group_id: int
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": OWNERSHIP_RECORD_SCHEMA,
            "pid": self.pid,
            "owner_pid": self.owner_pid,
            "process_identity": self.process_identity,
            "owner_identity": self.owner_identity,
            "executable": self.executable,
            "process_group_id": self.process_group_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: object) -> _OwnershipRecord:
        if not isinstance(payload, dict):
            raise ValueError("ownership record must be a JSON object")
        if payload.get("schema_version") != OWNERSHIP_RECORD_SCHEMA:
            raise ValueError("unsupported ownership record schema")

        integer_fields = ("pid", "owner_pid", "process_group_id")
        values: dict[str, int] = {}
        for name in integer_fields:
            value = payload.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"invalid {name}")
            values[name] = value

        if values["pid"] == values["owner_pid"]:
            raise ValueError("child PID cannot equal owner PID")
        if values["process_group_id"] != values["pid"]:
            raise ValueError("owned process group must be led by the child PID")

        strings: dict[str, str] = {}
        for name in ("process_identity", "owner_identity", "executable"):
            value = payload.get(name)
            if not isinstance(value, str) or not value.strip() or "\x00" in value:
                raise ValueError(f"invalid {name}")
            strings[name] = value

        created_at = payload.get("created_at")
        if not isinstance(created_at, int | float) or isinstance(created_at, bool):
            raise ValueError("invalid created_at")

        return cls(
            pid=values["pid"],
            owner_pid=values["owner_pid"],
            process_identity=strings["process_identity"],
            owner_identity=strings["owner_identity"],
            executable=strings["executable"],
            process_group_id=values["process_group_id"],
            created_at=float(created_at),
        )


class _ActivityClock:
    def __init__(self, started_at: float) -> None:
        self._last_activity = started_at
        self._lock = threading.Lock()

    def touch(self, timestamp: float) -> None:
        with self._lock:
            self._last_activity = max(self._last_activity, timestamp)

    def arm(self, timestamp: float) -> None:
        """Begin measuring inactivity from *timestamp*.

        Called once, after the process is launched and output monitoring is
        fully in place, so that process-launch and supervisor-setup time is
        never charged against the output-inactivity budget.
        """
        self.touch(timestamp)

    def inactive_for(self, timestamp: float) -> float:
        with self._lock:
            return max(0.0, timestamp - self._last_activity)


class OwnedProcessSupervisor:
    """Run one subprocess at a time with isolated cancellation and tree cleanup.

    Explicit cancellation sets the shared ``cancellation_event``.  A timeout
    never sets that event, so a timed-out attempt cannot poison a later retry or
    job.  Call :meth:`reset` only when beginning a new job after cancellation,
    or create a fresh supervisor per job/attempt.
    """

    def __init__(
        self,
        limits: ProcessLimits | None = None,
        *,
        cancellation_event: threading.Event | None = None,
        ownership_record: str | os.PathLike[str] | None = None,
        hide_window: bool = True,
    ) -> None:
        self.limits = limits or ProcessLimits()
        self.cancellation_event = cancellation_event or threading.Event()
        self.ownership_record = Path(ownership_record) if ownership_record is not None else None
        self.hide_window = hide_window
        self._state_lock = threading.Lock()
        self._active_process: subprocess.Popen[bytes] | None = None
        self._active_identity: _ProcessIdentity | None = None
        self._running = False

    @property
    def current_pid(self) -> int | None:
        """Return the active owned PID without exposing its process handle."""
        with self._state_lock:
            process = self._active_process
            if process is None or process.poll() is not None:
                return None
            return process.pid

    @property
    def running(self) -> bool:
        with self._state_lock:
            return self._running

    def cancel(self) -> None:
        """Request cancellation; the monitor thread owns process termination."""
        self.cancellation_event.set()

    def reset(self) -> None:
        """Clear an earlier explicit cancellation while no attempt is active."""
        with self._state_lock:
            if self._running:
                raise RuntimeError("cannot reset cancellation while a process is running")
            self.cancellation_event.clear()

    def run(
        self,
        args: Sequence[str | os.PathLike[str]],
        *,
        stdin_data: str | bytes | None = None,
        cwd: str | os.PathLike[str] | None = None,
        env: Mapping[str, str] | None = None,
        stdout_callback: OutputCallback | None = None,
        stderr_callback: OutputCallback | None = None,
        status_callback: StatusCallback | None = None,
        cancel_requested: CancelCallback | None = None,
    ) -> ProcessResult:
        """Run an argv-only command and return or raise after complete cleanup.

        ``stdin_data`` is written through a pipe and is never persisted in the
        ownership record.  Non-whitespace stdout or stderr immediately resets
        the inactivity timer.  Output callbacks run on daemon reader threads;
        GUI callers should bridge them through their normal signal mechanism.
        """
        command = _validate_command(args)
        payload = _encode_stdin(stdin_data)

        with self._state_lock:
            if self._running:
                raise RuntimeError("this supervisor already has an active process")
            self._running = True

        started_at = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        identity: _ProcessIdentity | None = None
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        reader_threads: list[threading.Thread] = []
        stdin_thread: threading.Thread | None = None
        outcome = ProcessOutcome.EXITED
        forced_kill = False
        returncode: int | None = None
        activity = _ActivityClock(started_at)

        try:
            if self._is_cancelled(cancel_requested):
                result = ProcessResult(
                    args=command,
                    pid=None,
                    returncode=None,
                    outcome=ProcessOutcome.CANCELLED,
                    stdout="",
                    stderr="",
                    elapsed_seconds=0.0,
                )
                raise ProcessCancelledError("Process cancelled before launch.", result)

            process = self._spawn(command, payload is not None, cwd=cwd, env=env)
            identity = _process_identity(process.pid)
            if identity is None:
                if process.poll() is None:
                    _terminate_unrecorded_process(process, self.limits)
                    raise ProcessLaunchError(
                        f"Could not capture creation identity for owned PID {process.pid}."
                    )
                # A very short-lived command may exit before identity capture.
                # It no longer needs tree recovery, but its output/result remain useful.
                identity = _ProcessIdentity(
                    token=f"already-exited:{process.pid}",
                    executable=command[0],
                )

            with self._state_lock:
                self._active_process = process
                self._active_identity = identity

            if self.ownership_record is not None and process.poll() is None:
                try:
                    self._write_ownership_record(process.pid, identity)
                except Exception as exc:
                    _terminate_owned_process_tree(process, identity, self.limits)
                    raise ProcessLaunchError(
                        f"Could not persist ownership for PID {process.pid}; "
                        "the owned tree was terminated."
                    ) from exc

            reader_threads = [
                _start_output_reader(
                    process.stdout,
                    stdout_parts,
                    stdout_callback,
                    activity,
                    name=f"owned-process-{process.pid}-stdout",
                ),
                _start_output_reader(
                    process.stderr,
                    stderr_parts,
                    stderr_callback,
                    activity,
                    name=f"owned-process-{process.pid}-stderr",
                ),
            ]
            if payload is not None:
                stdin_thread = _start_stdin_writer(process.stdin, payload, process.pid)

            _emit_status(status_callback, process.pid, ProcessPhase.STARTED, 0.0, 0.0)
            next_status_at = started_at + self.limits.status_interval

            # The total-timeout clock intentionally runs from ``started_at``, but
            # inactivity must only measure the monitored window. Arm it here, now
            # that the process is launched, its creation identity captured, the
            # ownership record persisted and the stdout/stderr readers plus any
            # stdin writer are running. Otherwise launch and setup time counts as
            # "no meaningful process output" and a healthy child can be killed
            # for inactivity it never caused.
            activity.arm(time.monotonic())

            while True:
                returncode = process.poll()
                if returncode is not None:
                    break

                now = time.monotonic()
                elapsed = max(0.0, now - started_at)
                inactive = activity.inactive_for(now)

                if self._is_cancelled(cancel_requested):
                    outcome = ProcessOutcome.CANCELLED
                    _emit_status(
                        status_callback,
                        process.pid,
                        ProcessPhase.CANCELLING,
                        elapsed,
                        inactive,
                    )
                    break
                if elapsed >= self.limits.total_timeout:
                    outcome = ProcessOutcome.TOTAL_TIMEOUT
                    _emit_status(
                        status_callback,
                        process.pid,
                        ProcessPhase.TOTAL_TIMEOUT,
                        elapsed,
                        inactive,
                    )
                    break
                if inactive >= self.limits.inactivity_timeout:
                    outcome = ProcessOutcome.INACTIVITY_TIMEOUT
                    _emit_status(
                        status_callback,
                        process.pid,
                        ProcessPhase.INACTIVITY_TIMEOUT,
                        elapsed,
                        inactive,
                    )
                    break

                if now >= next_status_at:
                    _emit_status(
                        status_callback,
                        process.pid,
                        ProcessPhase.ACTIVE,
                        elapsed,
                        inactive,
                    )
                    next_status_at = now + self.limits.status_interval

                self.cancellation_event.wait(self.limits.poll_interval)

            if outcome != ProcessOutcome.EXITED and process.poll() is None:
                forced_kill = _terminate_owned_process_tree(process, identity, self.limits)
                returncode = process.poll()

            if process.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    returncode = process.wait(timeout=self.limits.force_kill_wait)
            else:
                returncode = process.returncode

        finally:
            if process is not None:
                if process.poll() is None:
                    if identity is not None:
                        forced_kill = (
                            _terminate_owned_process_tree(process, identity, self.limits)
                            or forced_kill
                        )
                    else:
                        _terminate_unrecorded_process(process, self.limits)
                _close_stdin(process.stdin)
                if stdin_thread is not None:
                    stdin_thread.join(timeout=self.limits.pipe_join_timeout)
                _finish_output_readers(process, reader_threads, self.limits.pipe_join_timeout)

                if self.ownership_record is not None and process.poll() is not None:
                    _remove_record(self.ownership_record)

            with self._state_lock:
                self._active_process = None
                self._active_identity = None
                self._running = False

        elapsed = max(0.0, time.monotonic() - started_at)
        pid = process.pid if process is not None else None
        result = ProcessResult(
            args=command,
            pid=pid,
            returncode=returncode,
            outcome=outcome,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
            elapsed_seconds=elapsed,
            forced_kill=forced_kill,
        )
        if pid is not None:
            _emit_status(
                status_callback,
                pid,
                ProcessPhase.EXITED,
                elapsed,
                activity.inactive_for(time.monotonic()),
            )

        if outcome == ProcessOutcome.CANCELLED:
            raise ProcessCancelledError("Process cancelled by user.", result)
        if outcome == ProcessOutcome.INACTIVITY_TIMEOUT:
            raise ProcessInactivityTimeoutError(
                f"No meaningful process output for {self.limits.inactivity_timeout:g} seconds.",
                result,
            )
        if outcome == ProcessOutcome.TOTAL_TIMEOUT:
            raise ProcessTotalTimeoutError(
                f"Process exceeded the {self.limits.total_timeout:g}-second total limit.",
                result,
            )
        return result

    def _is_cancelled(self, callback: CancelCallback | None) -> bool:
        if self.cancellation_event.is_set():
            return True
        if callback is None:
            return False
        try:
            return bool(callback())
        except Exception:
            return False

    def _spawn(
        self,
        command: tuple[str, ...],
        pipe_stdin: bool,
        *,
        cwd: str | os.PathLike[str] | None,
        env: Mapping[str, str] | None,
    ) -> subprocess.Popen[bytes]:
        kwargs: dict[str, Any] = {
            "stdin": subprocess.PIPE if pipe_stdin else subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "close_fds": True,
            "cwd": os.fspath(cwd) if cwd is not None else None,
            "env": dict(env) if env is not None else None,
            "bufsize": 0,
        }
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if self.hide_window:
                flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
            kwargs["creationflags"] = flags
        else:
            kwargs["start_new_session"] = True

        return subprocess.Popen(command, **kwargs)  # noqa: S603 - argv only, shell disabled

    def _write_ownership_record(self, pid: int, identity: _ProcessIdentity) -> None:
        if self.ownership_record is None:
            return
        owner = _process_identity(os.getpid())
        if owner is None:
            raise ProcessLaunchError("Could not capture the supervisor process identity.")
        record = _OwnershipRecord(
            pid=pid,
            owner_pid=os.getpid(),
            process_identity=identity.token,
            owner_identity=owner.token,
            executable=identity.executable,
            process_group_id=pid,
            created_at=time.time(),
        )
        _atomic_write_json(self.ownership_record, record.to_dict())


def recover_owned_process(
    record_path: str | os.PathLike[str],
    *,
    termination_grace: float = DEFAULT_TERMINATION_GRACE_SECONDS,
    force_kill_wait: float = DEFAULT_FORCE_KILL_WAIT_SECONDS,
) -> RecoveryResult:
    """Terminate a crashed owner's recorded tree after exact identity checks.

    The command line and process name are deliberately irrelevant.  Recovery
    proceeds only when the original owner is gone and the recorded PID still
    has the exact creation identity captured immediately after spawn.
    """
    path = Path(record_path)
    if not path.exists():
        return RecoveryResult(RecoveryState.NO_RECORD)
    if termination_grace <= 0 or force_kill_wait <= 0:
        raise ValueError("recovery wait limits must be positive")

    try:
        if path.stat().st_size > 65_536:
            raise ValueError("ownership record is too large")
        record = _OwnershipRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        _remove_record(path)
        return RecoveryResult(RecoveryState.INVALID_RECORD, detail=str(exc))

    if record.pid == os.getpid():
        return RecoveryResult(
            RecoveryState.IDENTITY_MISMATCH,
            record.pid,
            "record targets the current application process",
        )

    owner = _process_identity(record.owner_pid)
    if owner is not None and owner.token == record.owner_identity:
        return RecoveryResult(
            RecoveryState.OWNER_ACTIVE,
            record.pid,
            "the original supervisor is still active",
        )

    current = _process_identity(record.pid)
    if current is None:
        _remove_record(path)
        return RecoveryResult(RecoveryState.PROCESS_GONE, record.pid)
    if current.token != record.process_identity:
        _remove_record(path)
        return RecoveryResult(
            RecoveryState.IDENTITY_MISMATCH,
            record.pid,
            "PID was reused or the process identity changed",
        )

    terminated = _terminate_recovered_tree(
        record,
        termination_grace=termination_grace,
        force_kill_wait=force_kill_wait,
    )
    if terminated:
        _remove_record(path)
        return RecoveryResult(RecoveryState.TERMINATED, record.pid)
    return RecoveryResult(
        RecoveryState.FAILED,
        record.pid,
        "owned process tree did not exit within the bounded cleanup period",
    )


def is_process_running(pid: int) -> bool:
    """Return whether a positive PID currently resolves to a live identity."""
    return pid > 0 and _process_identity(pid) is not None


def process_creation_identity(pid: int) -> str | None:
    """Return a stable, sanitized identity for one exact process lifetime.

    The underlying token includes the OS process creation identity and resolved
    executable.  Persisting only its SHA-256 digest lets other recovery systems
    protect against PID reuse without writing executable paths into ownership
    records.
    """

    identity = (
        _windows_process_identity(pid, fail_on_unknown=True)
        if os.name == "nt"
        else _process_identity(pid)
    )
    if identity is None:
        return None
    return hashlib.sha256(identity.token.encode("utf-8")).hexdigest()


def _validate_command(args: Sequence[str | os.PathLike[str]]) -> tuple[str, ...]:
    if isinstance(args, str | bytes | os.PathLike):
        raise TypeError("args must be an argv sequence, not a shell command string")
    command: list[str] = []
    for arg in args:
        value = os.fsdecode(os.fspath(arg))
        if "\x00" in value:
            raise ValueError("command arguments cannot contain NUL bytes")
        command.append(value)
    if not command or not command[0].strip():
        raise ValueError("command must contain a non-empty executable")
    return tuple(command)


def _encode_stdin(data: str | bytes | None) -> bytes | None:
    if data is None:
        return None
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, bytes):
        return data
    raise TypeError("stdin_data must be str, bytes, or None")


def _start_output_reader(
    pipe: BinaryIO | None,
    sink: list[str],
    callback: OutputCallback | None,
    activity: _ActivityClock,
    *,
    name: str,
) -> threading.Thread:
    def read_output() -> None:
        if pipe is None:
            return
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while True:
                chunk = pipe.read(4096)
                if not chunk:
                    break
                text = decoder.decode(chunk)
                if not text:
                    continue
                sink.append(text)
                if text.strip():
                    activity.touch(time.monotonic())
                    _safe_output_callback(callback, text)
            final_text = decoder.decode(b"", final=True)
            if final_text:
                sink.append(final_text)
                if final_text.strip():
                    activity.touch(time.monotonic())
                    _safe_output_callback(callback, final_text)
        except (OSError, ValueError):
            return
        finally:
            with contextlib.suppress(OSError):
                pipe.close()

    thread = threading.Thread(target=read_output, name=name, daemon=True)
    thread.start()
    return thread


def _safe_output_callback(callback: OutputCallback | None, text: str) -> None:
    if callback is None:
        return
    with contextlib.suppress(Exception):
        callback(text)


def _start_stdin_writer(pipe: BinaryIO | None, payload: bytes, pid: int) -> threading.Thread:
    def write_input() -> None:
        if pipe is None:
            return
        try:
            pipe.write(payload)
            pipe.flush()
        except (BrokenPipeError, OSError, ValueError):
            return
        finally:
            with contextlib.suppress(OSError):
                pipe.close()

    thread = threading.Thread(
        target=write_input,
        name=f"owned-process-{pid}-stdin",
        daemon=True,
    )
    thread.start()
    return thread


def _emit_status(
    callback: StatusCallback | None,
    pid: int,
    phase: ProcessPhase,
    elapsed: float,
    inactive: float,
) -> None:
    if callback is None:
        return
    status = ProcessStatus(
        pid=pid,
        phase=phase,
        elapsed_seconds=max(0.0, elapsed),
        inactive_seconds=max(0.0, inactive),
    )
    with contextlib.suppress(Exception):
        callback(status)


def _close_stdin(pipe: BinaryIO | None) -> None:
    if pipe is not None:
        with contextlib.suppress(OSError, ValueError):
            pipe.close()


def _finish_output_readers(
    process: subprocess.Popen[bytes],
    threads: list[threading.Thread],
    join_timeout: float,
) -> None:
    deadline = time.monotonic() + join_timeout
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    for pipe in (process.stdout, process.stderr):
        if pipe is not None:
            with contextlib.suppress(OSError, ValueError):
                pipe.close()
    for thread in threads:
        if thread.is_alive():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))


def _terminate_unrecorded_process(
    process: subprocess.Popen[bytes],
    limits: ProcessLimits,
) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt" and process.pid > 0 and process.pid != os.getpid():
        _run_taskkill(process.pid, force=False, timeout=limits.termination_grace)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=limits.termination_grace)
        if process.poll() is None:
            _run_taskkill(process.pid, force=True, timeout=limits.force_kill_wait)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=limits.force_kill_wait)
        return
    with contextlib.suppress(Exception):
        process.terminate()
        process.wait(timeout=limits.termination_grace)
    if process.poll() is None:
        with contextlib.suppress(Exception):
            process.kill()
            process.wait(timeout=limits.force_kill_wait)


def _terminate_owned_process_tree(
    process: subprocess.Popen[bytes],
    identity: _ProcessIdentity,
    limits: ProcessLimits,
) -> bool:
    """Return whether force-kill escalation was required."""
    if process.poll() is not None:
        return False
    current = _process_identity(process.pid)
    if current is None or current.token != identity.token or process.pid == os.getpid():
        return False

    if os.name == "nt":
        _run_taskkill(process.pid, force=False, timeout=limits.termination_grace)
    else:
        _signal_posix_group(process.pid, signal.SIGTERM)

    try:
        process.wait(timeout=limits.termination_grace)
        return False
    except subprocess.TimeoutExpired:
        pass

    current = _process_identity(process.pid)
    if current is None or current.token != identity.token:
        return False

    if os.name == "nt":
        _run_taskkill(process.pid, force=True, timeout=limits.force_kill_wait)
    else:
        _signal_posix_group(process.pid, signal.SIGKILL)

    try:
        process.wait(timeout=limits.force_kill_wait)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            process.kill()
            process.wait(timeout=limits.force_kill_wait)
    return True


def _terminate_recovered_tree(
    record: _OwnershipRecord,
    *,
    termination_grace: float,
    force_kill_wait: float,
) -> bool:
    if not _record_identity_matches(record):
        return True

    if os.name == "nt":
        _run_taskkill(record.pid, force=False, timeout=termination_grace)
    else:
        _signal_posix_group(record.process_group_id, signal.SIGTERM)
    if _wait_for_identity_exit(record, termination_grace):
        return True

    if not _record_identity_matches(record):
        return True
    if os.name == "nt":
        _run_taskkill(record.pid, force=True, timeout=force_kill_wait)
    else:
        _signal_posix_group(record.process_group_id, signal.SIGKILL)
    return _wait_for_identity_exit(record, force_kill_wait)


def _record_identity_matches(record: _OwnershipRecord) -> bool:
    current = _process_identity(record.pid)
    return current is not None and current.token == record.process_identity


def _wait_for_identity_exit(record: _OwnershipRecord, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _record_identity_matches(record):
            return True
        time.sleep(min(DEFAULT_POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
    return not _record_identity_matches(record)


def _run_taskkill(pid: int, *, force: bool, timeout: float) -> None:
    if pid <= 0 or pid == os.getpid() or os.name != "nt":
        return
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    executable = Path(system_root) / "System32" / "taskkill.exe"
    args = [str(executable), "/PID", str(pid), "/T"]
    if force:
        args.append("/F")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(  # noqa: S603 - fixed system executable and validated numeric PID
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
            close_fds=True,
            timeout=max(0.1, timeout),
            creationflags=creationflags,
        )


def _signal_posix_group(group_id: int, sig: signal.Signals) -> None:
    if os.name == "nt" or group_id <= 0:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if group_id != os.getpgrp():
            os.killpg(group_id, sig)


def _process_identity(pid: int) -> _ProcessIdentity | None:
    if pid <= 0:
        return None
    if os.name == "nt":
        return _windows_process_identity(pid)
    return _procfs_process_identity(pid)


def _windows_process_identity(
    pid: int, *, fail_on_unknown: bool = False
) -> _ProcessIdentity | None:
    if os.name != "nt":
        return None
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    get_process_times = kernel32.GetProcessTimes
    get_process_times.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
    ]
    get_process_times.restype = wintypes.BOOL
    get_exit_code = kernel32.GetExitCodeProcess
    get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_exit_code.restype = wintypes.BOOL
    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    query_image.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    process_query_limited_information = 0x1000
    handle = open_process(process_query_limited_information, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if fail_on_unknown and error != 87:  # ERROR_INVALID_PARAMETER means no such PID.
            if error == 5:
                raise PermissionError(error, "Process identity query was denied")
            raise OSError(error, "Process identity query failed")
        return None
    try:
        exit_code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            if fail_on_unknown:
                error = ctypes.get_last_error()
                raise OSError(error, "Process exit-state query failed")
            return None
        if exit_code.value != 259:  # STILL_ACTIVE
            return None

        created = FileTime()
        exited = FileTime()
        kernel = FileTime()
        user = FileTime()
        if not get_process_times(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            if fail_on_unknown:
                error = ctypes.get_last_error()
                raise OSError(error, "Process creation-time query failed")
            return None

        length = wintypes.DWORD(32_768)
        buffer = ctypes.create_unicode_buffer(length.value)
        if not query_image(handle, 0, buffer, ctypes.byref(length)):
            if fail_on_unknown:
                error = ctypes.get_last_error()
                if error == 5:
                    raise PermissionError(error, "Process image query was denied")
                raise OSError(error, "Process image query failed")
            return None
        executable = os.path.normcase(os.path.realpath(buffer.value))
        creation_ticks = (int(created.high) << 32) | int(created.low)
        return _ProcessIdentity(
            token=f"windows:{creation_ticks}:{executable}",
            executable=executable,
        )
    finally:
        close_handle(handle)


def _procfs_process_identity(pid: int) -> _ProcessIdentity | None:
    proc = Path("/proc") / str(pid)
    try:
        stat_text = (proc / "stat").read_text(encoding="utf-8")
        closing_paren = stat_text.rfind(")")
        if closing_paren < 0:
            return None
        fields_after_name = stat_text[closing_paren + 2 :].split()
        start_ticks = fields_after_name[19]
        executable = os.path.realpath(os.readlink(proc / "exe"))
    except (OSError, IndexError, ValueError):
        return None
    return _ProcessIdentity(
        token=f"procfs:{start_ticks}:{executable}",
        executable=executable,
    )


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _remove_record(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


__all__ = [
    "DEFAULT_FORCE_KILL_WAIT_SECONDS",
    "DEFAULT_INACTIVITY_TIMEOUT_SECONDS",
    "DEFAULT_STATUS_INTERVAL_SECONDS",
    "DEFAULT_TERMINATION_GRACE_SECONDS",
    "DEFAULT_TOTAL_TIMEOUT_SECONDS",
    "OwnedProcessSupervisor",
    "ProcessCancelledError",
    "ProcessControlError",
    "ProcessInactivityTimeoutError",
    "ProcessLaunchError",
    "ProcessLimits",
    "ProcessOutcome",
    "ProcessPhase",
    "ProcessResult",
    "ProcessStatus",
    "ProcessTotalTimeoutError",
    "RecoveryResult",
    "RecoveryState",
    "is_process_running",
    "recover_owned_process",
]
