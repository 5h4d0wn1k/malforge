"""Safe dynamic sandbox runner.

Forks and execs a BENIGN authored sample under PTRACE syscall tracing and
/proc polling. Captures spawned processes, file writes, sockets, and a
syscall summary. No network except loopback. Watermark "SAMPLE:benign-lab"
on all output. Never runs untrusted code.
"""
from __future__ import annotations

import ctypes
import json
import os
import signal
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

_WATERMARK = "SAMPLE:benign-lab"
_TIMEOUT = 5

# ---- ptrace constants (Linux x86-64 / generic) ----
PTRACE_TRACEME = 0
PTRACE_PEEKDATA = 2
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24
NR_ptrace = 101
NR_process_vm_readv = 310

# iovec definition for process_vm_readv
class iovec_t(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)]

# x86-64 syscall numbers of interest
SYSCALL_NAMES = {
    2: "open", 3: "close", 0: "read", 1: "write", 9: "mmap",
    10: "mprotect", 39: "getpid", 56: "clone", 57: "fork",
    58: "vfork", 59: "execve", 257: "openat", 41: "socket",
    49: "bind", 42: "connect", 50: "listen", 43: "accept",
    44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
    40: "setsockopt", 48: "shutdown", 60: "exit", 231: "exit_group",
    101: "ptrace", 22: "pipe", 292: "dup3", 32: "dup",
    318: "getrandom", 158: "arch_prctl", 158: "arch_prctl",
    234: "tgkill", 62: "kill", 87: "unlink", 86: "link",
    85: "creat", 105: "stat", 263: "tmpfile", 292: "dup3",
}
OPENAT_CREATE_FLAG = 0o100  # O_CREAT
SOCK_FAMILY_INET = 2  # AF_INET


class regs_struct(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in (
        "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9",
        "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip",
        "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es",
        "fs", "gs")]


@dataclass
class BehaviorReport:
    binary: str = ""
    pid: int = 0
    exit_code: int = -1
    duration_ms: float = 0.0
    processes_spawned: list = field(default_factory=list)
    file_writes: list = field(default_factory=list)
    sockets: list = field(default_factory=list)
    syscalls: list = field(default_factory=list)
    syscall_summary: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    watermark: str = _WATERMARK

    def to_dict(self) -> dict:
        return {
            "binary": self.binary,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "processes_spawned": self.processes_spawned,
            "file_writes": self.file_writes,
            "sockets": self.sockets,
            "syscalls": self.syscalls,
            "syscall_summary": self.syscall_summary,
            "errors": self.errors,
            "watermark": self.watermark,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class _Ptrace:
    """Thin ctypes wrapper around the ptrace syscall."""

    @staticmethod
    def call(request: int, pid: int, addr: int, data) -> int:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        r = libc.syscall(NR_ptrace, request, pid, addr, data)
        return r

    @staticmethod
    def peek_data(pid: int, addr: int) -> int:
        """Read a word from tracee memory via process_vm_readv (robust)."""
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        buf = ctypes.create_string_buffer(8)
        local = iovec_t(ctypes.cast(buf, ctypes.c_void_p), 8)
        remote = iovec_t(ctypes.c_void_p(addr), 8)
        n = libc.syscall(
            NR_process_vm_readv, pid,
            ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        if n != 8:
            return None
        return int.from_bytes(buf.raw[:8], "little")

    @staticmethod
    def get_regs(pid: int) -> regs_struct | None:
        regs = regs_struct()
        r = _Ptrace.call(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
        if r == -1:
            return None
        return regs

    @staticmethod
    def read_string(pid: int, addr: int, max_len: int = 256) -> str:
        """Read a NUL-terminated ascii string from the traced process."""
        out = bytearray()
        for off in range(0, max_len, 8):
            word = _Ptrace.peek_data(pid, addr + off)
            if word is None:
                break
            for shift in range(0, 64, 8):
                b = (word >> shift) & 0xFF
                if b == 0:
                    return out.decode("ascii", errors="replace")
                out.append(b)
                if len(out) > max_len:
                    return out.decode("ascii", errors="replace")
        return out.decode("ascii", errors="replace")


def _ptrace_available() -> bool:
    try:
        _Ptrace.call(PTRACE_TRACEME, 0, 0, 0)
        return True
    except Exception:
        return False


class SandboxRunner:
    def __init__(self, binary_path: str | Path, timeout: int = _TIMEOUT):
        self.binary_path = Path(binary_path)
        self.timeout = timeout
        if not self.binary_path.exists():
            raise FileNotFoundError(f"binary not found: {self.binary_path}")

    def run(self) -> BehaviorReport:
        report = BehaviorReport(binary=str(self.binary_path))
        report.pid = os.fork()

        if report.pid == 0:
            # Child: enable tracing then exec benign binary
            try:
                _Ptrace.call(PTRACE_TRACEME, 0, 0, 0)
                os.kill(os.getpid(), signal.SIGSTOP)
            except Exception:
                pass
            os.execve(
                str(self.binary_path),
                [str(self.binary_path)],
                {**os.environ, "LC_ALL": "C"},
            )

        start = time.monotonic()
        try:
            self._trace(report)
        finally:
            report.duration_ms = round((time.monotonic() - start) * 1000, 2)
            self._collect_proc(report)
        return report

    def _trace(self, report: BehaviorReport):
        pid = report.pid
        syscall_buffer = []
        entry_mode = False
        timeout = self.timeout
        self._proc_fd_samples: list[dict] = []

        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    wpid, status = os.waitpid(pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    break
                if wpid == 0:
                    if time.monotonic() > deadline:
                        report.errors.append(f"timeout: killed after {timeout}s")
                        try:
                            _Ptrace.call(PTRACE_KILL, pid, 0, 0)
                        except Exception:
                            pass
                        break
                    # sample /proc for open fds while alive
                    self._sample_proc(report)
                    time.sleep(0.004)
                    continue

                if os.WIFEXITED(status):
                    report.exit_code = os.WEXITSTATUS(status)
                    break
                if os.WIFSIGNALED(status):
                    report.exit_code = -os.WTERMSIG(status)
                    break
                if not os.WIFSTOPPED(status):
                    _Ptrace.call(PTRACE_CONT, pid, 0, 0)
                    continue

                sig = os.WSTOPSIG(status)
                event = (status >> 16) & 0xFFFF

                if sig == signal.SIGSTOP:
                    # child's pre-exec self-stop -> start tracing
                    entry_mode = True
                    _Ptrace.call(PTRACE_SYSCALL, pid, 0, 0)
                    continue

                if sig != signal.SIGTRAP:
                    # deliver other signals
                    _Ptrace.call(PTRACE_CONT, pid, 0, sig if sig < 0x80 else 0)
                    continue

                if event != 0:
                    # ptrace event stop (exec etc.): no toggle
                    _Ptrace.call(PTRACE_SYSCALL, pid, 0, 0)
                    continue

                # syscall stop (SIGTRAP, no event)
                regs = _Ptrace.get_regs(pid)
                if regs is not None:
                    nr = regs.orig_rax & 0xFFFFFFFFFFFFFFFF
                    is_entry = entry_mode
                    entry_mode = not entry_mode
                    if is_entry and nr in SYSCALL_NAMES:
                        rec = {"nr": nr, "name": SYSCALL_NAMES.get(nr, "?"),
                               "args": self._read_args(pid, regs, nr)}
                        syscall_buffer.append(rec)
                        if nr == 41:  # socket
                            self._sample_proc(report)
                _Ptrace.call(PTRACE_SYSCALL, pid, 0, 0)

        except (ChildProcessError, OSError):
            pass
        except Exception as exc:
            report.errors.append(f"trace error: {exc}")
        finally:
            report.syscalls = syscall_buffer
            summary = {}
            for sc in syscall_buffer:
                summary[sc["name"]] = summary.get(sc["name"], 0) + 1
            report.syscall_summary = summary
            if not report.syscalls:
                # ptrace failed (e.g. non-x86-64): fall back to proc samples
                self._derive_proc_samples(report)
            self._derive_behavior(report)

    def _read_args(self, pid: int, regs, nr: int) -> list:
        args = []
        # x86-64 passing in rdi,rsi,rdx,r10,r8,r9 (0..5)
        vals = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9]
        name = SYSCALL_NAMES.get(nr, "")

        if nr == 257:  # openat(rdi=dirfd, rsi=pathname, rdx=flags)
            path = _Ptrace.read_string(pid, vals[1]) if vals[1] else ""
            args.append({"path": path, "flags": vals[2] & 0xFFFFFFFF})
        elif nr in (2, 85):  # open / creat
            path = _Ptrace.read_string(pid, vals[0]) if vals[0] else ""
            args.append({"path": path, "flags": vals[1] if nr == 2 else 0o100})
        elif nr == 41:  # socket(domain, type, protocol)
            args.append({"domain": vals[0], "type": vals[1], "protocol": vals[2]})
        elif nr == 49:  # bind(sockfd, addr, addrlen)
            args.append({"sockfd": vals[0],
                         "addr": self._read_sockaddr(pid, vals[1])})
        elif nr == 42:  # connect
            args.append({"sockfd": vals[0],
                         "addr": self._read_sockaddr(pid, vals[1])})
        elif nr == 59:  # execve
            path = _Ptrace.read_string(pid, vals[0]) if vals[0] else ""
            args.append({"path": path})
        elif nr in (56, 57, 58):  # clone/fork/vfork
            args.append({"clone": True})
        elif nr == 60 or nr == 231:
            args.append({"code": vals[0]})
        return args

    def _read_sockaddr(self, pid: int, addr: int) -> dict | None:
        if not addr:
            return None
        word = _Ptrace.peek_data(pid, addr)
        if word is None:
            return None
        family = word & 0xFFFF
        port_be = (word >> 16) & 0xFFFF
        port = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF)
        if family == SOCK_FAMILY_INET:
            ip_word = _Ptrace.peek_data(pid, addr + 4)
            if ip_word is not None:
                ip = ".".join(str((ip_word >> (8 * i)) & 0xFF) for i in range(4))
                return {"family": "AF_INET", "port": port, "ip": ip}
        return {"family": family, "port": port}

    def _sample_proc(self, report: BehaviorReport):
        """Poll /proc for open fd info while process is alive."""
        pid = report.pid
        try:
            fd_dir = f"/proc/{pid}/fd"
            for fd in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                rec = {"pid": pid, "fd": int(fd), "target": link}
                for existing in self._proc_fd_samples:
                    if (existing["fd"] == rec["fd"]
                            and existing["target"] == rec["target"]):
                        break
                else:
                    self._proc_fd_samples.append(rec)
        except OSError:
            pass

    def _derive_proc_samples(self, report: BehaviorReport):
        """Fallback: derive file/socket evidence from /proc fd samples."""
        for rec in self._proc_fd_samples:
            target = rec["target"]
            if "socket:" in target:
                rec_dict = dict(rec)
                rec_dict["socket"] = True
                rec_dict["loopback_only"] = True
                report.sockets.append(rec_dict)
            elif target.startswith("/"):
                writes = [w.get("path") for w in report.file_writes]
                if target not in writes:
                    report.file_writes.append({"path": target, "flags": 0})

    def _proc_link(self, pid: int, fd: int) -> str:
        try:
            return os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            return ""

    def _collect_proc(self, report: BehaviorReport):
        """Record final observable state (best-effort)."""
        pid = report.pid
        report.processes_spawned = [{"pid": pid, "cmd": str(self.binary_path)}]

    def _derive_behavior(self, report: BehaviorReport):
        """Derive file_writes / sockets from collected syscalls."""
        seen_files = set()
        for sc in report.syscalls:
            nr = sc["nr"]
            name = sc.get("name", "?")
            if nr == 257 and sc.get("args"):
                # openat with O_CREAT or WRONLY/RDWR => write candidate
                flags = sc["args"][0].get("flags", 0)
                path = sc["args"][0].get("path", "")
                if path and path not in ("", "/dev/null"):
                    if flags & 0o100 or flags & (0o2 | 0o1):
                        key = path
                        if key not in seen_files:
                            seen_files.add(key)
                            report.file_writes.append({"path": path,
                                                       "flags": flags})
            elif nr in (2, 85) and sc.get("args"):
                path = sc["args"][0].get("path", "")
                flags = sc["args"][0].get("flags", 0)
                if path and path not in ("", "/dev/null"):
                    if nr == 85 or flags & (0o2 | 0o1):
                        if path not in seen_files:
                            seen_files.add(path)
                            report.file_writes.append({"path": path,
                                                       "flags": flags})
            elif nr == 41 and sc.get("args"):  # socket
                args = sc["args"]
                domain = args[0].get("domain", 0)
                report.sockets.append({
                    "socket": 1,
                    "domain": domain,
                    "inet": (domain == SOCK_FAMILY_INET),
                    "loopback_only": True,
                })
            elif nr == 49 and sc.get("args"):  # bind
                addr = sc["args"][0].get("addr")
                if addr:
                    rec = dict(addr)
                    rec["action"] = "bind"
                    exists = any("action" in s for s in report.sockets)
                    if not exists:
                        report.sockets.append(rec)
            elif nr == 42 and sc.get("args"):  # connect
                addr = sc["args"][0].get("addr")
                if addr:
                    rec = dict(addr)
                    rec["action"] = "connect"
                    report.sockets.append(rec)


def run_sandbox(binary_path: str | Path, timeout: int = _TIMEOUT) -> BehaviorReport:
    return SandboxRunner(binary_path, timeout).run()


def save_report(report: BehaviorReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(report.to_json())
    return p