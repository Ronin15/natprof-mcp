"""
natprof-mcp — macOS native profiling + debugging over MCP.

Profiling (`sample`/atos/vmmap), leaks, and LLDB on one session keyed to a pid.
The agent never touches paths, slides, ports, or `protocol-server`.

Profiling is built on /usr/bin/sample, not xctrace — it ships with the
Command Line Tools (no full Xcode.app required) and, unlike an LLDB
`process interrupt`, never holds the whole process suspended: it briefly
thread_suspends one thread at a time to read its stack, so latency-sensitive
threads (audio callbacks, a render loop, network I/O) keep running between
samples instead of stalling.

Correctness model — symbols are either right or the call fails:
  * Images are SNAPSHOT at open_session. Symbolication reads the frozen copy,
    so rebuilding mid-session cannot corrupt a trace.
  * Every image's LC_UUID is captured at open_session and re-verified before
    every atos call. UUID changes iff the binary changes — unlike mtime, which
    both false-positives (touch, git checkout, ccache) and false-negatives
    (copied trace file).
  * dSYM UUID is checked against the binary UUID separately. A stale dSYM is a
    different bug than a rebuilt binary, and the snapshot does not catch it.
  * atos failure yields the hex address, never a guessed symbol.

Any Mach-O + DWARF: C, C++, Rust, Swift, Go, Zig.
"""

import bisect
import os
import pty
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid as _uuidmod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("natprof", instructions=__doc__)

SYSTEM_PREFIXES = ("/usr/lib/", "/System/", "/Library/Apple/")
SENTINEL = "<<<NATPROF_EOC>>>"
WORKDIR = Path(tempfile.gettempdir()) / "natprof"


class ToolError(RuntimeError):
    """A wrapped CLI tool exited non-zero. Carries stderr so callers get an
    actionable message instead of a bare exit code."""


def sh(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        detail = (r.stderr or r.stdout).strip()
        raise ToolError(f"`{' '.join(cmd)}` failed ({r.returncode}): {detail}")
    return r.stdout


def _sample_missing_hint():
    return ("`/usr/bin/sample` was not found. It ships with the Xcode Command "
            "Line Tools — run `xcode-select --install`.")


def _is_system(p):
    return p.startswith(SYSTEM_PREFIXES)


# =============================================================== identity

def mach_uuid(path) -> Optional[str]:
    """LC_UUID of a Mach-O image or a dSYM's DWARF. Changes iff the binary
    changes. This is the only sound identity check; mtime is not."""
    try:
        out = sh(["dwarfdump", "--uuid", str(path)])
    except (ToolError, FileNotFoundError):
        return None
    m = re.search(r"UUID:\s*([0-9A-Fa-f-]{36})", out)
    return m.group(1).upper() if m else None


def dsym_dwarf(dsym_path) -> list[Path]:
    d = Path(dsym_path) / "Contents/Resources/DWARF"
    return sorted(d.iterdir()) if d.is_dir() else []


# =================================================================== LLDB

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _reject_unsafe(*values: str) -> None:
    """`Lldb.cmd()` writes text straight into a pty, so a caller-supplied
    string containing a newline/CR would terminate the current command early
    and inject an arbitrary second one. Only relevant where plain data (a
    path, an arg, an env value) gets embedded into command text — debug()'s
    entire contract is "run any lldb command", so it's exempt by design."""
    for v in values:
        if "\n" in v or "\r" in v:
            raise ValueError(
                f"{v!r} contains a newline/CR — refused: lldb commands are sent "
                f"as literal text over a pty, and a newline would inject an "
                f"extra command")


class Lldb:
    """Persistent lldb interpreter over a pty. Each command is followed by an
    echoed sentinel so we know exactly where its output ends."""

    def __init__(self, lldb_bin: str = "lldb"):
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(
            [lldb_bin, "--no-use-colors", "-x"],
            stdin=slave, stdout=slave, stderr=slave, text=True, close_fds=True)
        os.close(slave)
        self._drain(3.0)
        self.stopped = False

    def attach(self, pid: int) -> None:
        out = self.cmd(f"attach -p {pid}")
        if "error" in out.lower():
            self.close()
            raise RuntimeError(
                f"lldb attach failed on pid {pid}: {' '.join(out.split()[:12])}. "
                f"Usually the target lacks the get-task-allow entitlement. "
                f"Debug builds have it; a codesigned release build does not.")
        self.cmd("process continue")   # attach STOPS the target; a halted
        self.stopped = False           # process yields zero samples.

    def launch(self, path: str, args: Optional[list[str]] = None,
               env: Optional[dict[str, str]] = None, cwd: Optional[str] = None) -> int:
        """Launches fresh instead of attaching to something already running —
        the only way to set env vars before the target's first instruction
        executes. Always stops at the user entry point (`-m`, i.e. right
        before `main()`), not the raw process entry point (`-s`): confirmed
        live that `-s` fires before dyld has loaded a single dependent
        library (only the binary itself + dyld show up in `image list`),
        while `-m` fires only once dyld has fully resolved everything — the
        same completeness attach's post-attach vmmap snapshot relies on.
        Resuming afterward, if wanted, is the caller's job, not this
        method's."""
        args = args or []
        env = env or {}
        _reject_unsafe(path, *args, *env.values())
        for k in env:
            if not _ENV_NAME_RE.match(k):
                raise ValueError(f"invalid environment variable name {k!r}")

        out = self.cmd(f"target create -- {shlex.quote(path)}")
        if "error" in out.lower():
            self.close(kill=True)
            raise RuntimeError(f"lldb target create failed for {path}: "
                               f"{' '.join(out.split()[:20])}")

        # -n (--no-stdio): without this, the launched process's own stdout/
        # stderr shares this same pty with lldb's control channel — every
        # command after launch gets flooded with interleaved child output,
        # confirmed live (a "process kill" response came back as a wall of
        # the target's own stdout/stderr instead of a kill confirmation, and
        # the process was still alive afterward because the actual kill
        # command got lost in that noise).
        flags = ["-m", "-n"]
        if cwd:
            flags += ["-w", shlex.quote(cwd)]
        for k, v in env.items():
            flags += ["-E", shlex.quote(f"{k}={v}")]
        arglist = f" -- {' '.join(shlex.quote(a) for a in args)}" if args else ""
        out = self.cmd(f"process launch {' '.join(flags)}{arglist}", timeout=20)
        if "error" in out.lower():
            self.close(kill=True)
            raise RuntimeError(f"lldb process launch failed for {path}: "
                               f"{' '.join(out.split()[:30])}")

        # `process launch -m`'s breakpoint-hit notification is asynchronous
        # and can arrive well after our sentinel already closed out the
        # command above — confirmed live, and a fixed-duration drain isn't
        # reliable (under load it lagged past 1.5s and corrupted the next
        # command's output). Poll actual process state instead of guessing a
        # delay: any "stopped" text — whether it's GetState()'s own answer or
        # a late-arriving leaked notification — is equally valid evidence the
        # process is stopped by that point.
        state = ""
        for _ in range(100):  # up to ~10s
            state = self.cmd("script print(lldb.process.GetState())")
            if "stopped" in state.lower():
                break
            time.sleep(0.1)
        else:
            self.close(kill=True)
            raise RuntimeError(f"launched {path} but it never reached a stopped "
                               f"state: {state!r}")
        self._drain(0.3)   # flush any trailing async text before parsing pid

        pid_out = self.cmd("script print(lldb.process.GetProcessID())")
        m = re.search(r"\d+", pid_out)
        if not m:
            self.close(kill=True)
            raise RuntimeError(f"launched {path} but could not read its pid: {pid_out}")
        self.stopped = True
        return int(m.group())

    def _drain(self, timeout=0.3):
        buf, end = "", time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    buf += os.read(self.master, 65536).decode(errors="replace")
                except OSError:
                    break
                end = time.time() + 0.1
        return buf

    def cmd(self, command: str, timeout: float = 30.0) -> str:
        os.write(self.master, (command + "\n").encode())
        os.write(self.master, f"script print('{SENTINEL}')\n".encode())
        buf, end = "", time.time() + timeout
        while buf.count(SENTINEL) < 2 and time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.1)
            if r:
                buf += os.read(self.master, 65536).decode(errors="replace")
        lines = [l for l in buf.splitlines()
                 if SENTINEL not in l and not l.startswith("(lldb) script")]
        if lines and command in lines[0]:
            lines = lines[1:]
        return "\n".join(lines).strip()

    def close(self, kill: bool = False, pid: Optional[int] = None):
        try:
            self.cmd("process kill" if kill else "detach", timeout=5)
        except Exception:
            pass
        if kill and pid is not None:
            # Hard guarantee independent of whatever happened above: the
            # pty-based "process kill" already silently failed once in
            # testing (its own confirmation was drowned out by interleaved
            # child stdout before the -n fix, and the broad except above
            # would have hidden that). A direct signal doesn't depend on
            # lldb having parsed anything correctly.
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            self.proc.terminate()
        except Exception:
            pass
        try:
            os.close(self.master)
        except OSError:
            pass


def _find_lldb() -> str:
    """Apple's bundled lldb lags upstream. Prefer Homebrew LLVM when present."""
    for p in ("/opt/homebrew/opt/llvm/bin/lldb", "/usr/local/opt/llvm/bin/lldb"):
        if Path(p).exists():
            return p
    return "lldb"


def _ensure_lldb(s: "Session") -> Lldb:
    """Attach lazily, on first actual use. LLDB attach is a hard task_suspend
    of the whole process — unlike sample-based profiling, there's no way to
    make it gentler. Deferring it means a profiling-only session never pays
    that freeze."""
    if s.lldb is None:
        lldb = Lldb(_find_lldb())
        lldb.attach(s.pid)
        s.lldb = lldb
    return s.lldb


# ================================================================== state

@dataclass
class Image:
    start: int
    end: int
    path: str            # original on-disk path
    uuid: Optional[str]  # LC_UUID at session open
    frozen: str          # snapshot copy we symbolicate against
    dsym: Optional[str] = None


@dataclass
class Session:
    pid: int
    sid: str
    images: list
    lldb: Optional[Lldb] = None
    trace: Optional[str] = None
    recording_proc: Optional[subprocess.Popen] = None   # in-flight record()
    recording_out: Optional[str] = None                 # its output path
    baseline: Optional[dict] = None
    warnings: list = field(default_factory=list)

    def lookup(self, addr) -> Optional[Image]:
        starts = [i.start for i in self.images]
        k = bisect.bisect_right(starts, addr) - 1
        if k < 0:
            return None
        img = self.images[k]
        return img if img.start <= addr < img.end else None

    def workdir(self) -> Path:
        return WORKDIR / self.sid


SESSIONS: dict[str, Session] = {}


def _sess(sid) -> Session:
    if sid not in SESSIONS:
        raise ValueError(f"unknown session {sid}. Call open_session first.")
    return SESSIONS[sid]


def _vmmap_images(pid):
    try:
        out = sh(["vmmap", str(pid)])
    except ToolError as e:
        raise RuntimeError(f"vmmap failed on pid {pid}: {e} — allow Terminal under "
                           f"System Settings > Privacy & Security > Developer Tools.")
    seen, imgs = set(), []
    for line in out.splitlines():
        if "__TEXT" not in line:
            continue
        m = re.search(r"([0-9a-f]{8,16})-([0-9a-f]{8,16})", line)
        parts = line.split()
        path = parts[-1] if parts else ""
        if not m or not path.startswith("/") or path in seen:
            continue
        seen.add(path)
        imgs.append((int(m.group(1), 16), int(m.group(2), 16), path))
    if not imgs:
        raise RuntimeError("no __TEXT regions parsed from vmmap")
    return sorted(imgs)


def _snapshot(sid, raw_images, dsym_paths):
    """Freeze app images + record UUIDs. Rebuilds after this cannot corrupt us."""
    snapdir = WORKDIR / sid / "images"
    snapdir.mkdir(parents=True, exist_ok=True)

    # index dSYMs by the UUID they claim to describe
    dsym_by_uuid = {}
    for d in dsym_paths:
        for dw in dsym_dwarf(d):
            u = mach_uuid(dw)
            if u:
                dsym_by_uuid[u] = str(dw)

    images, warnings = [], []
    for start, end, path in raw_images:
        if _is_system(path):
            images.append(Image(start, end, path, None, path))
            continue
        u = mach_uuid(path)
        dst = snapdir / f"{start:016x}-{Path(path).name}"
        try:
            shutil.copy2(path, dst)
            frozen = str(dst)
        except OSError as e:
            warnings.append(f"could not snapshot {Path(path).name}: {e}")
            frozen = path
        dsym = dsym_by_uuid.get(u) if u else None
        if u and not dsym and dsym_by_uuid:
            warnings.append(
                f"{Path(path).name} (UUID {u}) has no matching dSYM among the "
                f"{len(dsym_by_uuid)} provided — those dSYMs are for other builds")
        images.append(Image(start, end, path, u, frozen, dsym))
    return images, warnings


# ================================================================== parse

# `sample`'s report draws its call tree with 2-char indent tokens ("+ ", "! ",
# ": ", "| ", "  ") before each frame; depth = how many tokens precede it.
_SAMPLE_TOKEN_RE = re.compile(r"^[+!:| ] ")
_SAMPLE_COUNT_RE = re.compile(r"^(\d+)\s")
_SAMPLE_ADDR_RE = re.compile(r"\[([0-9a-fA-Fx,]+)\]")


def _strip_sample_indent(s):
    depth = 0
    while len(s) >= 2 and _SAMPLE_TOKEN_RE.match(s[:2]):
        depth += 1
        s = s[2:]
    return depth, s


class _SampleNode:
    __slots__ = ("depth", "count", "addr", "children")

    def __init__(self, depth, count, addr):
        self.depth = depth
        self.count = count
        self.addr = addr
        self.children = []


def _parse_sample_tree(report_path):
    """Parses a `sample` report's "Call graph:" section into a per-thread
    forest of _SampleNode. Only counts and raw addresses are trusted from the
    report — symbol/image text is NOT used, since `sample` resolves it by
    reading whatever is currently on disk at the image's path, which a
    mid-session rebuild can silently replace. Re-symbolication goes through
    the UUID-verified _symbolicate() pipeline instead, same as every other
    address in this file."""
    lines = Path(report_path).read_text(errors="replace").splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.strip() == "Call graph:") + 1
    except StopIteration:
        raise RuntimeError("`sample` report has no 'Call graph:' section — "
                           "unexpected output format.")
    end = next((i for i, l in enumerate(lines[start:], start)
               if l.strip().startswith("Total number in stack")), len(lines))

    threads = []
    stack = []  # ancestor chain of _SampleNode, innermost last
    for raw in lines[start:end]:
        if not raw.startswith("    "):
            continue
        depth, rest = _strip_sample_indent(raw[4:])
        m = _SAMPLE_COUNT_RE.match(rest)
        if not m:
            continue
        count = int(m.group(1))
        addrs = _SAMPLE_ADDR_RE.findall(rest)
        if not addrs:
            # thread header line ("<count> Thread_NNN ... (serial)") — no
            # frame address, just a new thread's root; reset the stack.
            threads.append([])
            stack = []
            continue
        addr = int(addrs[-1].split(",")[0], 16)
        node = _SampleNode(depth, count, addr)
        while stack and stack[-1].depth >= depth:
            stack.pop()
        if stack:
            stack[-1].children.append(node)
        elif threads:
            threads[-1].append(node)
        stack.append(node)
    if not threads:
        raise RuntimeError("zero threads parsed from the sample report — "
                           "unexpected output format.")
    return threads  # list[list[_SampleNode]]: one root list per thread


def _self_counts(threads):
    """Leaf (self-time) sample count per raw address, summed across threads."""
    counts = Counter()

    def walk(node):
        self_n = node.count - sum(c.count for c in node.children)
        if self_n > 0:
            counts[node.addr] += self_n
        for c in node.children:
            walk(c)

    for roots in threads:
        for r in roots:
            walk(r)
    return counts


def _dominant_path(roots):
    """The most-sampled root, then greedily the most-sampled child at each
    level — a representative "what was this thread doing" backtrace."""
    if not roots:
        return [], 0
    node = max(roots, key=lambda n: n.count)
    path = [node.addr]
    weight = node.count
    while node.children:
        node = max(node.children, key=lambda c: c.count)
        path.append(node.addr)
    return path, weight


def _leaf_addrs(report_path):
    counts = _self_counts(_parse_sample_tree(report_path))
    if not counts:
        raise RuntimeError("zero samples parsed from the sample report.")
    return counts


def _symbolicate(addrs, s: Session):
    """One atos per image, each with its own slide. UUID verified first.
    Cross-image symbolication and stale-binary symbolication are impossible here.

    Images are grouped by `start` address (a plain int) rather than by the
    Image object itself: dataclasses with eq=True/frozen=False (the default)
    are unhashable, so using Image instances as dict keys raises TypeError."""
    groups = defaultdict(list)
    img_by_start = {}
    unmapped = []
    for a in addrs:
        img = s.lookup(a)
        if img is None:
            unmapped.append(a)
            continue
        img_by_start[img.start] = img
        groups[img.start].append(a)

    out = {}
    for start, grp in groups.items():
        img = img_by_start[start]
        if img.uuid:
            # the frozen copy must still be the image that was loaded
            if mach_uuid(img.frozen) != img.uuid:
                raise RuntimeError(
                    f"snapshot of {Path(img.path).name} no longer matches its "
                    f"LC_UUID {img.uuid}. Session state is corrupt; reopen it.")
            if img.dsym and mach_uuid(img.dsym) != img.uuid:
                raise RuntimeError(
                    f"dSYM for {Path(img.path).name} has UUID "
                    f"{mach_uuid(img.dsym)} but the loaded image is {img.uuid}. "
                    f"Wrong dSYM — symbols would be fiction.")
        target = img.dsym or img.frozen
        try:
            res = sh(["atos", "-o", target, "-l", hex(img.start),
                      *[hex(a) for a in grp]]).strip().splitlines()
            for a, sym in zip(grp, res):
                # atos embeds its own "(in <target-basename>)" in each line,
                # which is the frozen-snapshot filename, not the real image
                # name — strip it since we already report `image` separately.
                sym = re.sub(r"\s+\(in [^)]*\)", "", sym, count=1)
                out[a] = (sym, Path(img.path).name)
        except ToolError:
            for a in grp:
                out[a] = (hex(a), Path(img.path).name)   # honest failure
    for a in unmapped:
        out[a] = (hex(a), "?")
    return out


# ================================================================== tools

def _session_result(s: Session, **extra) -> dict:
    """Shared response shape for open_session and launch_session — both
    produce a session over a pid with a snapshotted image set."""
    app = [i for i in s.images if not _is_system(i.path)]
    return {
        "session_id": s.sid, "pid": s.pid,
        "images_total": len(s.images), "images_snapshotted": len(app),
        "app_images": [{"name": Path(i.path).name, "uuid": i.uuid,
                        "load_address": hex(i.start),
                        "dsym": bool(i.dsym)} for i in app[:12]],
        "warnings": s.warnings,
        **extra,
    }


@mcp.tool()
def open_session(pid: int, dsym_paths: Optional[list[str]] = None,
                  attach_debugger: bool = False) -> dict:
    """Open a session on a running process. Captures ASLR slides and LC_UUIDs,
    and snapshots every non-system image. After this call you may rebuild
    freely — symbolication uses the frozen copies.

    LLDB is NOT attached by default: attach is a hard task_suspend of the
    whole process (unlike sample-based profiling, which never fully halts
    it), so a profiling-only session shouldn't pay that freeze. debug() and
    backtrace_all() attach lazily on first use; pass attach_debugger=True
    here only if you specifically want it up front.

    dsym_paths are matched to images by UUID, not filename.

    Returns {session_id, pid, images_total, images_snapshotted, app_images:
    [{name, uuid, load_address, dsym} for up to the first 12 non-system
    images], warnings, debugger}."""
    sid = _uuidmod.uuid4().hex[:8]
    raw = _vmmap_images(pid)
    images, warnings = _snapshot(sid, raw, dsym_paths or [])
    s = Session(pid=pid, sid=sid, images=images, warnings=warnings)

    dbg = "not requested"
    if attach_debugger:
        try:
            lldb = Lldb(_find_lldb())
            lldb.attach(pid)
            s.lldb = lldb
            dbg = "attached (running)"
        except RuntimeError as e:
            dbg = f"not attached: {e}"

    SESSIONS[sid] = s
    return _session_result(s, debugger=dbg)


@mcp.tool()
def launch_session(path: str, args: Optional[list[str]] = None,
                    env: Optional[dict[str, str]] = None,
                    cwd: Optional[str] = None,
                    dsym_paths: Optional[list[str]] = None,
                    mem_debug: bool = False,
                    stop_at_entry: bool = False) -> dict:
    """Launch a fresh binary under LLDB, instead of attaching to a pid that's
    already running. This is the only way to set environment variables before
    the target's first instruction executes — open_session() only ever
    attaches to something already past that point, so MallocStackLogging
    can't be turned on retroactively for leaks() (see mem_debug below).

    Every launch stops right before main() first internally — the raw
    process entry point fires before dyld has loaded a single dependent
    library (confirmed live: only the binary itself shows up in the image
    list at that point), so this waits for the one point where dyld has
    fully resolved everything and no user code has run yet; images are
    snapshotted there, same idea as open_session's snapshot of an attached
    pid. If stop_at_entry=False (default, matching
    open_session's attach_debugger=False — don't leave things halted unless
    asked), the process is resumed before this call returns. Pass
    stop_at_entry=True to leave it halted so you can debug()-set breakpoints
    first, then debug(session_id, "process continue") yourself.

    mem_debug=True sets MallocStackLogging=1 so leaks() returns real
    allocation backtraces instead of just a count. Off by default — it adds
    malloc-path overhead for the life of the process, same reasoning as
    attach_debugger defaulting off.

    cwd defaults to wherever this server process itself runs from; pass it
    explicitly for targets that resolve relative paths (config files, data
    directories, etc.) against their own launch directory rather than an
    absolute path.

    path/args/env values may not contain a newline or carriage return.

    close_session() on a launch_session-created session kills the process
    (it's ours to clean up); on an open_session-created one it only detaches.

    Returns the same shape as open_session, plus {mem_debug, stopped_at_entry,
    launch_path}; `debugger` is always "attached (launched)" since this tool
    always launches under LLDB."""
    p = str(Path(path).expanduser())
    if not Path(p).is_file():
        raise ValueError(f"{p} does not exist or is not a file")
    env = dict(env or {})
    if mem_debug:
        env.setdefault("MallocStackLogging", "1")

    lldb = Lldb(_find_lldb())
    pid = lldb.launch(p, args, env, cwd=cwd)

    sid = _uuidmod.uuid4().hex[:8]
    raw = _vmmap_images(pid)
    images, warnings = _snapshot(sid, raw, dsym_paths or [])
    s = Session(pid=pid, sid=sid, images=images, warnings=warnings, lldb=lldb)
    SESSIONS[sid] = s

    if not stop_at_entry:
        lldb.cmd("process continue")
        lldb.stopped = False

    return _session_result(s, debugger="attached (launched)", mem_debug=mem_debug,
                           stopped_at_entry=stop_at_entry, launch_path=p)


@mcp.tool()
def debug(session_id: str, command: str) -> str:
    """Run any LLDB command: `bt`, `thread list`, `frame variable`, `expr`,
    `breakpoint set -n foo`, `watchpoint`, `memory read`.

    Stopping the process halts sampling; record() auto-resumes. Attaches LLDB
    on first call if the session doesn't have it yet — that attach briefly
    freezes the whole process."""
    s = _sess(session_id)
    lldb = _ensure_lldb(s)
    out = lldb.cmd(command)
    c = command.strip()
    if c.startswith(("b ", "breakpoint", "process interrupt", "watchpoint")):
        lldb.stopped = True
    if "process continue" in c or c == "c":
        lldb.stopped = False
    return out or "(no output)"


@mcp.tool()
def backtrace_all(session_id: str) -> str:
    """Interrupt, dump every thread's backtrace, resume.

    This fully halts the process (LLDB `process interrupt` is a whole-process
    task_suspend) for as long as the dump takes, which is disruptive to
    anything latency-sensitive — audio glitches, dropped frames, timed-out
    connections. For a much lower-impact "what's every thread doing right
    now" snapshot, use light_backtrace() instead — reach for this one only
    when you need actual LLDB commands (expr, breakpoints, frame variable)
    on top of the stacks."""
    s = _sess(session_id)
    lldb = _ensure_lldb(s)
    lldb.cmd("process interrupt")
    bt = lldb.cmd("thread backtrace all", timeout=60)
    lldb.cmd("process continue")
    lldb.stopped = False
    return bt


@mcp.tool()
def light_backtrace(session_id: str, seconds: int = 1) -> dict:
    """Low-impact "what's every thread doing" snapshot via `sample`, instead
    of an LLDB `process interrupt`. The process is never fully halted —
    `sample` suspends one thread at a time just long enough to read its
    stack — so this is safe to run against latency-sensitive processes
    (audio, rendering, networking) where backtrace_all would cause a visible
    stall.

    Trade-off: it's not a single instant — it's the dominant (most-sampled)
    call path per thread over `seconds`, so a thread doing several different
    things in that window collapses to whichever path won most samples.
    `weight`/`total` on each thread tells you how dominant that path was.

    Returns {seconds, threads: [{frames: [{symbol, image}] (root to leaf),
    weight, total_samples}]}. weight/total_samples is that thread's
    dominant-path share for this window."""
    s = _sess(session_id)
    if not shutil.which("sample"):
        raise RuntimeError(_sample_missing_hint())
    out = str(s.workdir() / "light.txt")
    s.workdir().mkdir(parents=True, exist_ok=True)
    sh(["sample", str(s.pid), str(seconds), "1", "-mayDie", "-file", out])
    threads = _parse_sample_tree(out)

    all_addrs = set()
    dominant = []
    for roots in threads:
        path, weight = _dominant_path(roots)
        total = sum(r.count for r in roots)
        all_addrs.update(path)
        dominant.append((path, weight, total))

    syms = _symbolicate(all_addrs, s)
    threads_out = []
    for path, weight, total in dominant:
        frames = [{"symbol": syms[a][0], "image": syms[a][1]} for a in path]
        threads_out.append({"frames": frames, "weight": weight, "total_samples": total})
    return {"seconds": seconds, "threads": threads_out}


def _collect_recording(s: Session) -> bool:
    """Finalizes an in-flight record() if `sample` has exited. Returns True
    once s.trace is ready, False if it's still running. Raises RuntimeError
    if `sample` exited non-zero. Only call with s.recording_proc set."""
    assert s.recording_proc is not None
    ret = s.recording_proc.poll()
    if ret is None:
        return False
    _, stderr = s.recording_proc.communicate()
    s.recording_proc = None
    if ret != 0:
        raise RuntimeError(f"sample recording failed ({ret}): {stderr.strip()}")
    s.trace = s.recording_out
    s.recording_out = None
    return True


@mcp.tool()
def record(session_id: str, seconds: int = 10, interval_ms: int = 1) -> dict:
    """Start a stack-sampling profile via `sample`, in the background — this
    returns immediately rather than blocking the caller for `seconds`. MCP
    tool calls are otherwise synchronous: a client with no way to background
    a call would be stuck fully blocked for the whole recording, with no
    visibility into progress and no way to bail out. Poll record_status()
    to find out when it's ready, then call hotspots().

    No Xcode required, and unlike an LLDB `process interrupt` the target is
    never fully halted — `sample` briefly suspends one thread at a time to
    read its stack, so latency-sensitive threads keep running between
    samples. Auto-resumes the process first if LLDB has it stopped, since a
    halted process yields zero samples."""
    s = _sess(session_id)
    if not shutil.which("sample"):
        raise RuntimeError(_sample_missing_hint())
    if s.recording_proc is not None and s.recording_proc.poll() is None:
        raise RuntimeError("a recording is already in progress on this "
                           "session. Call record_status() first.")
    if s.lldb and s.lldb.stopped:
        s.lldb.cmd("process continue")
        s.lldb.stopped = False
    out = str(s.workdir() / "sample.txt")
    s.workdir().mkdir(parents=True, exist_ok=True)
    s.recording_proc = subprocess.Popen(
        ["sample", str(s.pid), str(seconds), str(interval_ms), "-mayDie", "-file", out],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    s.recording_out = out
    return {"status": "recording", "seconds": seconds, "interval_ms": interval_ms}


@mcp.tool()
def record_status(session_id: str) -> dict:
    """Check on a record() that was started in the background. Returns
    {status: "running"} while `sample` is still collecting, or {status:
    "done", report} once the trace is ready for hotspots() — report is the
    path to the raw `sample` output, not a parsed result; hotspots() is what
    actually reads it. Raises ValueError if record() was never called on
    this session, and RuntimeError if `sample` itself exited non-zero."""
    s = _sess(session_id)
    if s.recording_proc is None:
        if s.trace:
            return {"status": "done", "report": s.trace}
        raise ValueError("no recording in this session. Call record() first.")
    if _collect_recording(s):
        return {"status": "done", "report": s.trace}
    return {"status": "running"}


@mcp.tool()
def hotspots(session_id: str, top_n: int = 20, include_system: bool = False) -> dict:
    """Symbolicated self-time hotspots from the last completed record(). System
    frames excluded by default — they dominate leaf counts and say nothing.
    Symbols are UUID-verified or the call fails; there is no stale-symbol path.

    `pct` on each hotspot is always computed against `total_samples` (every
    sample in the recording, system included), never against
    `attributed_samples` (what's left after the include_system filter) — so
    with include_system=False, percentages will look small whenever system
    code dominates the recording, even if the listed hotspots are 100% of
    your app's own time. Compare attributed_samples/total_samples to see how
    much of the recording was system overhead versus app code before reading
    individual pct values as "how hot is this".

    Returns {total_samples, attributed_samples, hotspots: [{symbol, image,
    samples, pct}]}."""
    s = _sess(session_id)
    if s.recording_proc is not None and not _collect_recording(s):
        raise ValueError("recording still in progress. Call record_status() "
                         "to check, then retry once it reports \"done\".")
    if not s.trace:
        raise ValueError("no trace in session. Call record() first.")
    counts = _leaf_addrs(s.trace)
    total = sum(counts.values())
    if not include_system:
        counts = Counter({a: n for a, n in counts.items()
                          if (i := s.lookup(a)) and not _is_system(i.path)})
    hot = counts.most_common(top_n)
    syms = _symbolicate([a for a, _ in hot], s)
    return {"total_samples": total, "attributed_samples": sum(counts.values()),
            "hotspots": [{"symbol": syms[a][0], "image": syms[a][1], "samples": n,
                          "pct": round(100.0 * n / total, 2)} for a, n in hot]}


@mcp.tool()
def set_baseline(session_id: str) -> dict:
    """Snapshot the top 100 current hotspots as the comparison baseline for a
    later compare() call. Internally calls hotspots(top_n=100), so it needs a
    completed record() first — same "call record_status() until done"
    requirement, and it raises the same errors hotspots() would if no trace
    exists yet.

    Typical flow: record() -> poll record_status() -> set_baseline() ->
    change or exercise the target -> record() again -> poll record_status()
    -> compare(). Calling set_baseline() again overwrites the previous
    baseline for this session.

    Returns {baseline_symbols}."""
    s = _sess(session_id)
    s.baseline = hotspots(session_id, top_n=100)
    return {"baseline_symbols": len(s.baseline["hotspots"])}


@mcp.tool()
def compare(session_id: str, threshold_pct: float = 1.0) -> dict:
    """Diff the baseline set by set_baseline() against a fresh hotspots()
    reading taken right now — so a new record()/record_status() cycle must
    complete after set_baseline() and before calling this, or you're just
    comparing the baseline against itself. Keyed on image!symbol, since two
    dylibs can both export process(). Only symbols whose pct grew by at
    least threshold_pct show up in `regressions`; a symbol missing from the
    baseline is treated as 0.0 base_pct (a new hotspot, not just a bigger
    one).

    Returns {threshold_pct, regressed, regressions: [{symbol, base_pct,
    new_pct, delta}]} sorted by delta descending."""
    s = _sess(session_id)
    if not s.baseline:
        raise ValueError("no baseline. Call set_baseline() first.")
    key = lambda h: f'{h["image"]}!{h["symbol"]}'
    base = {key(h): h["pct"] for h in s.baseline["hotspots"]}
    new = hotspots(session_id, top_n=100)
    regs = [{"symbol": key(h), "base_pct": base.get(key(h), 0.0), "new_pct": h["pct"],
             "delta": round(h["pct"] - base.get(key(h), 0.0), 2)}
            for h in new["hotspots"] if h["pct"] - base.get(key(h), 0.0) >= threshold_pct]
    regs.sort(key=lambda r: -r["delta"])
    return {"threshold_pct": threshold_pct, "regressed": bool(regs), "regressions": regs}


@mcp.tool()
def leaks(session_id: str) -> dict:
    """Leak check. LeakSanitizer's at-exit detection does not work on Darwin arm64,
    so `leaks` is the route on Apple Silicon.

    Backtraces in the report require MallocStackLogging to have been set before
    the target process launched; that cannot be enabled retroactively on an
    already-running process — which open_session-based sessions always are,
    since it only ever attaches to a pid that's already past that point. For
    real backtraces, start the session with launch_session(path, ...,
    mem_debug=True) instead: it launches the target fresh with
    MallocStackLogging=1 already in its environment before the first
    instruction runs.

    Returns {count, bytes, tail} — tail is the last 3000 chars of `leaks`'
    own output (entries + summary) with its trailing "Binary Images:" image
    dump already stripped, since that dump is often hundreds of KB and never
    useful here."""
    s = _sess(session_id)
    out = subprocess.run(["leaks", str(s.pid), "--list"],
                         capture_output=True, text=True).stdout
    m = re.search(r"(\d+) leaks? for (\d+) total leaked bytes", out)
    # `leaks` always appends a "Binary Images:" dump of every loaded library
    # after the actual leak entries — often hundreds of KB, and never useful
    # here. Cut it before taking the tail, or the tail is 100% guaranteed to
    # land inside that dump instead of showing any real leak/call-stack data.
    content = out.split("Binary Images:")[0]
    return {"count": int(m.group(1)) if m else 0,
            "bytes": int(m.group(2)) if m else 0, "tail": content[-3000:]}


@mcp.tool()
def verify(session_id: str) -> dict:
    """Re-check every snapshotted image against its recorded LC_UUID, and every
    dSYM against its image. Run this if you suspect the symbols.

    Returns {images: [{image, session_uuid, snapshot_ok, on_disk_uuid,
    rebuilt_since_open, dsym_matches}], all_ok}. rebuilt_since_open is a
    heads-up, not itself a failure — the frozen snapshot is what
    symbolication actually reads, so it's fine as long as snapshot_ok stays
    true; system images are skipped entirely and never appear in `images`."""
    s = _sess(session_id)
    rows = []
    for i in s.images:
        if _is_system(i.path) or not i.uuid:
            continue
        snap_ok = mach_uuid(i.frozen) == i.uuid
        disk = mach_uuid(i.path)
        rows.append({
            "image": Path(i.path).name,
            "session_uuid": i.uuid,
            "snapshot_ok": snap_ok,
            "on_disk_uuid": disk,
            "rebuilt_since_open": disk is not None and disk != i.uuid,
            "dsym_matches": (mach_uuid(i.dsym) == i.uuid) if i.dsym else None,
        })
    return {"images": rows,
            "all_ok": all(r["snapshot_ok"] and r["dsym_matches"] is not False
                          for r in rows)}


@mcp.tool()
def close_session(session_id: str, kill: bool = False) -> dict:
    """Detach LLDB, delete snapshots and trace, drop the session.

    Does NOT kill the process by default, even for a launch_session-created
    session: an LLDB-level kill (or SIGKILL) gives the target zero chance to
    run its own cleanup — closing files, releasing devices, flushing state —
    which can be visibly abrupt for anything holding a live resource (e.g. a
    process with an open audio output stream will audibly pop). A plain
    detach leaves that cleanup path intact; a kill doesn't. Left running,
    you can quit the target normally yourself and let its own shutdown path
    run. Pass kill=True to force it anyway — e.g. tearing down an automated
    test run where nobody's watching for a clean exit — and accept that
    cost."""
    s = SESSIONS.pop(session_id, None)
    if not s:
        return {"closed": None}
    if s.recording_proc is not None and s.recording_proc.poll() is None:
        s.recording_proc.terminate()
    if s.lldb:
        s.lldb.close(kill=kill, pid=s.pid)
    shutil.rmtree(s.workdir(), ignore_errors=True)
    return {"closed": session_id}


def main():
    if sys.platform != "darwin":
        print("natprof-mcp only runs on macOS (needs sample/atos/vmmap/lldb).",
              file=sys.stderr)
        sys.exit(1)
    mcp.run()


if __name__ == "__main__":
    main()
