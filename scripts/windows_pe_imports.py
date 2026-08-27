#!/usr/bin/env python3
"""Fail-closed inspection of imported DLLs from a Windows PE image."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading


FAILURE_TOKEN = "PE_IMPORT_INSPECTION_FAILED"
TIMEOUT_TOKEN = "PE_IMPORT_INSPECTION_TIMEOUT"
PE_BACKEND_TIMEOUT_SECONDS = 15
_DLL_NAME = r"[A-Za-z0-9_.+\-]+\.dll"
_DUMPBIN_DEPENDENCIES = re.compile(
    r"^\s*(" + _DLL_NAME + r")\s*$", re.IGNORECASE
)
_OBJDUMP_DEPENDENCY = re.compile(
    r"^\s*DLL Name:\s*(" + _DLL_NAME + r")\s*$", re.IGNORECASE
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print the normalized DLL imports of a Windows PE image."
    )
    parser.add_argument("pe", type=Path, help="PE image to inspect")
    return parser.parse_args()


def validate_mz(path: Path) -> None:
    try:
        if not path.is_file():
            raise ValueError("input does not begin with the PE MZ signature")
        with path.open("rb") as source:
            if source.read(2) != b"MZ":
                raise ValueError("input does not begin with the PE MZ signature")
    except OSError as error:
        raise ValueError(f"cannot read input: {error}") from error


def find_tool(executable_name: str) -> str | None:
    """Resolve an exact Windows .exe, with suffix-free non-Windows fixtures."""
    executable = shutil.which(f"{executable_name}.exe")
    if executable is not None or sys.platform.startswith("win"):
        return executable
    return shutil.which(executable_name)


def run_windows_job_command_streams(
    command: list[str],
    timeout_seconds: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str, bool]:
    """Run in a kill-on-close Job and capture stdout/stderr independently."""
    import ctypes
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class StartupInfoW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(SecurityAttributes),
        wintypes.DWORD,
    ]
    kernel32.CreatePipe.restype = wintypes.BOOL
    kernel32.SetHandleInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel32.SetHandleInformation.restype = wintypes.BOOL
    kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfoW),
        ctypes.POINTER(ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
    ]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    create_suspended = 0x00000004
    create_no_window = 0x08000000
    create_unicode_environment = 0x00000400
    startf_use_std_handles = 0x00000100
    handle_flag_inherit = 0x00000001
    job_object_extended_limit_information = 9
    job_object_limit_kill_on_job_close = 0x00002000
    wait_object_0 = 0
    wait_timeout = 0x00000102
    infinite = 0xFFFFFFFF
    error_broken_pipe = 109

    def close(handle: wintypes.HANDLE) -> None:
        if handle:
            kernel32.CloseHandle(handle)

    stdout_read = wintypes.HANDLE()
    stdout_write = wintypes.HANDLE()
    stderr_read = wintypes.HANDLE()
    stderr_write = wintypes.HANDLE()
    stdin_read = wintypes.HANDLE()
    stdin_write = wintypes.HANDLE()
    job = wintypes.HANDLE()
    process_info = ProcessInformation()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stream_errors: list[int] = []
    stdout_reader: threading.Thread | None = None
    stderr_reader: threading.Thread | None = None

    try:
        security = SecurityAttributes(
            ctypes.sizeof(SecurityAttributes),
            None,
            True,
        )
        if not kernel32.CreatePipe(
            ctypes.byref(stdout_read),
            ctypes.byref(stdout_write),
            ctypes.byref(security),
            0,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.SetHandleInformation(
            stdout_read, handle_flag_inherit, 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.CreatePipe(
            ctypes.byref(stderr_read),
            ctypes.byref(stderr_write),
            ctypes.byref(security),
            0,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.SetHandleInformation(
            stderr_read, handle_flag_inherit, 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.CreatePipe(
            ctypes.byref(stdin_read),
            ctypes.byref(stdin_write),
            ctypes.byref(security),
            0,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.SetHandleInformation(
            stdin_write, handle_flag_inherit, 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            job_object_limit_kill_on_job_close
        )
        if not kernel32.SetInformationJobObject(
            job,
            job_object_extended_limit_information,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        startup = StartupInfoW()
        startup.cb = ctypes.sizeof(StartupInfoW)
        startup.dwFlags = startf_use_std_handles
        startup.hStdInput = stdin_read
        startup.hStdOutput = stdout_write
        startup.hStdError = stderr_write
        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline(command)
        )
        environment_buffer = None
        environment_pointer = None
        creation_flags = create_suspended | create_no_window
        if env is not None:
            environment_text = "\0".join(
                f"{key}={value}"
                for key, value in sorted(
                    env.items(), key=lambda item: item[0].casefold()
                )
            ) + "\0\0"
            environment_buffer = ctypes.create_unicode_buffer(
                environment_text
            )
            environment_pointer = ctypes.cast(
                environment_buffer, wintypes.LPVOID
            )
            creation_flags |= create_unicode_environment
        if not kernel32.CreateProcessW(
            None,
            command_line,
            None,
            None,
            True,
            creation_flags,
            environment_pointer,
            None if cwd is None else str(cwd),
            ctypes.byref(startup),
            ctypes.byref(process_info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        close(stdout_write)
        stdout_write = wintypes.HANDLE()
        close(stderr_write)
        stderr_write = wintypes.HANDLE()
        close(stdin_read)
        stdin_read = wintypes.HANDLE()
        close(stdin_write)
        stdin_write = wintypes.HANDLE()

        if not kernel32.AssignProcessToJobObject(job, process_info.hProcess):
            error = ctypes.get_last_error()
            kernel32.TerminateProcess(process_info.hProcess, error or 1)
            raise ctypes.WinError(error)

        def read_stream(
            stream: wintypes.HANDLE,
            chunks: list[bytes],
        ) -> None:
            buffer = ctypes.create_string_buffer(65536)
            while True:
                read = wintypes.DWORD()
                if kernel32.ReadFile(
                    stream,
                    buffer,
                    len(buffer),
                    ctypes.byref(read),
                    None,
                ):
                    if read.value:
                        chunks.append(buffer.raw[: read.value])
                    continue
                error = ctypes.get_last_error()
                if error != error_broken_pipe:
                    stream_errors.append(error)
                return

        stdout_reader = threading.Thread(
            target=read_stream,
            args=(stdout_read, stdout_chunks),
            daemon=True,
        )
        stderr_reader = threading.Thread(
            target=read_stream,
            args=(stderr_read, stderr_chunks),
            daemon=True,
        )
        stdout_reader.start()
        stderr_reader.start()
        if kernel32.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            error = ctypes.get_last_error()
            kernel32.TerminateProcess(process_info.hProcess, error or 1)
            raise ctypes.WinError(error)
        close(process_info.hThread)
        process_info.hThread = wintypes.HANDLE()

        timeout_ms = min(timeout_seconds * 1000, 0xFFFFFFFE)
        wait_result = kernel32.WaitForSingleObject(
            process_info.hProcess, timeout_ms
        )
        timed_out = wait_result == wait_timeout
        if wait_result not in (wait_object_0, wait_timeout):
            raise ctypes.WinError(ctypes.get_last_error())

        close(job)
        job = wintypes.HANDLE()
        if timed_out:
            kernel32.WaitForSingleObject(process_info.hProcess, 5000)
        for reader in (stdout_reader, stderr_reader):
            if reader is not None:
                reader.join(2)
        alive_streams: list[str] = []
        if stdout_reader is not None and stdout_reader.is_alive():
            close(stdout_read)
            stdout_read = wintypes.HANDLE()
            stdout_reader.join(1)
            alive_streams.append("stdout")
        if stderr_reader is not None and stderr_reader.is_alive():
            close(stderr_read)
            stderr_read = wintypes.HANDLE()
            stderr_reader.join(1)
            alive_streams.append("stderr")
        if alive_streams:
            raise OSError(
                "Windows Job output pipe did not close after termination: "
                + ",".join(alive_streams)
            )
        if stream_errors:
            raise ctypes.WinError(stream_errors[0])

        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(
            process_info.hProcess, ctypes.byref(exit_code)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        stdout = b"".join(stdout_chunks).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_chunks).decode("utf-8", errors="replace")
        return int(exit_code.value), stdout, stderr, timed_out
    finally:
        close(job)
        if process_info.hProcess:
            kernel32.WaitForSingleObject(process_info.hProcess, 0)
        close(process_info.hThread)
        close(process_info.hProcess)
        close(stdout_write)
        close(stdout_read)
        close(stderr_write)
        close(stderr_read)
        close(stdin_write)
        close(stdin_read)


def run_windows_job_command(
    command: list[str],
    timeout_seconds: int,
    cwd: Path | None = None,
) -> tuple[int, str, bool]:
    """Compatibility wrapper for callers that require merged output."""
    exit_code, stdout, stderr, timed_out = run_windows_job_command_streams(
        command,
        timeout_seconds,
        cwd,
    )
    return exit_code, stdout + stderr, timed_out


def run_bounded_command(
    command: list[str],
    timeout_seconds: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str, bool]:
    if os.name == "nt":
        return run_windows_job_command_streams(
            command,
            timeout_seconds,
            cwd,
            env,
        )

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
    except OSError as error:
        raise OSError(str(error)) from error

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    stream_errors: list[OSError] = []

    def read_stream(stream, chunks: list[str]) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                chunks.append(chunk)
        except (OSError, ValueError) as error:
            stream_errors.append(OSError(str(error)))

    stdout_reader = threading.Thread(
        target=read_stream,
        args=(process.stdout, stdout_chunks),
        daemon=True,
    )
    stderr_reader = threading.Thread(
        target=read_stream,
        args=(process.stderr, stderr_chunks),
        daemon=True,
    )
    stdout_reader.start()
    stderr_reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
    group_error: OSError | None = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        group_error = error
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass

    for reader in (stdout_reader, stderr_reader):
        reader.join(2)
    alive_streams: list[str] = []
    if stdout_reader.is_alive():
        if process.stdout is not None:
            process.stdout.close()
        stdout_reader.join(1)
        alive_streams.append("stdout")
    if stderr_reader.is_alive():
        if process.stderr is not None:
            process.stderr.close()
        stderr_reader.join(1)
        alive_streams.append("stderr")
    if alive_streams:
        raise OSError(
            "POSIX process-group output pipe did not close after termination: "
            + ",".join(alive_streams)
        )
    if group_error is not None:
        raise group_error
    if stream_errors:
        raise stream_errors[0]

    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    return (
        process.returncode if process.returncode is not None else 124,
        stdout,
        stderr,
        timed_out,
    )


def run_tool(
    command: list[str],
    timeout_seconds: int = PE_BACKEND_TIMEOUT_SECONDS,
) -> tuple[int, str]:
    try:
        exit_code, stdout, stderr, timed_out = run_bounded_command(
            command,
            timeout_seconds,
        )
    except OSError as error:
        return 1, str(error)
    if timed_out:
        return (
            124,
            f"{TIMEOUT_TOKEN}: {command[0]} exceeded {timeout_seconds} seconds",
        )
    return exit_code, stdout + stderr


def parse_dumpbin(output: str) -> set[str]:
    dependencies: set[str] = set()
    in_dependencies = False
    for line in output.splitlines():
        normalized = line.strip().casefold()
        if normalized in {
            "image has the following dependencies:",
            "image has the following delay load dependencies:",
        }:
            in_dependencies = True
            continue
        if not in_dependencies:
            continue
        match = _DUMPBIN_DEPENDENCIES.fullmatch(line)
        if match is not None:
            dependencies.add(match.group(1).casefold())
        elif normalized:
            in_dependencies = False
    return dependencies


def parse_objdump(output: str) -> set[str]:
    return {
        match.group(1).casefold()
        for line in output.splitlines()
        if (match := _OBJDUMP_DEPENDENCY.fullmatch(line)) is not None
    }


def inspect_imports(path: Path) -> list[str]:
    validate_mz(path)

    backend_errors: list[str] = []
    dumpbin = find_tool("dumpbin")
    if dumpbin is not None:
        exit_code, output = run_tool([dumpbin, "/DEPENDENTS", str(path)])
        if exit_code == 0:
            imports = parse_dumpbin(output)
            if imports:
                return sorted(imports)
            backend_errors.append("dumpbin output contains no DLL imports")
        else:
            detail = output.strip()
            backend_errors.append(
                f"dumpbin exited {exit_code}"
                + (f": {detail}" if detail else "")
            )
    else:
        backend_errors.append("dumpbin.exe was not found")

    objdump = find_tool("objdump")
    if objdump is not None:
        exit_code, output = run_tool([objdump, "-p", str(path)])
        if exit_code == 0:
            imports = parse_objdump(output)
            if imports:
                return sorted(imports)
            backend_errors.append("objdump output contains no DLL imports")
        else:
            detail = output.strip()
            backend_errors.append(
                f"objdump exited {exit_code}"
                + (f": {detail}" if detail else "")
            )
    else:
        backend_errors.append("objdump.exe was not found")

    raise ValueError("; ".join(backend_errors))


def main() -> int:
    args = parse_args()
    try:
        imports = inspect_imports(args.pe)
    except ValueError as error:
        print(f"{FAILURE_TOKEN}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(imports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
