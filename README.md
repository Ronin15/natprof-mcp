# natprof-mcp

macOS native profiling and debugging over MCP. One session, keyed to a pid —
wraps `sample`, `atos`, `vmmap`, `leaks`, and `lldb` so an agent can profile,
symbolicate, and debug a running (or freshly launched) process without
touching paths, slides, ports, or `protocol-server` directly.

Works against any Mach-O + DWARF binary: C, C++, Rust, Swift, Go, Zig.

## How profiling works

`record`/`hotspots`/`light_backtrace` sample each thread's stack by briefly
suspending it one at a time, rather than freezing the whole process — audio
and render threads keep running between samples instead of glitching. This
is different from `backtrace_all`, which uses LLDB's `process interrupt` and
does freeze everything for as long as the dump takes; reach for that one
only when you need real LLDB commands (breakpoints, `expr`, `frame
variable`) alongside the stacks.

`record()` doesn't block for its `seconds` duration — MCP tool calls are
otherwise synchronous, so a caller with no way to background one would sit
fully frozen for the whole recording with no visibility and no way to bail
out. It returns immediately once `sample` is kicked off; poll
`record_status()` until it reports `"done"`, then call `hotspots()`.

## Correctness model

Symbols are either right or the call fails, never silently wrong:

- Images are snapshotted when a session opens. Symbolication reads the
  frozen copy, so rebuilding mid-session can't corrupt a trace.
- Every image's `LC_UUID` is captured at session-open and re-verified before
  every `atos` call. UUID changes iff the binary changes — unlike mtime,
  which both false-positives (touch, git checkout, ccache) and
  false-negatives (copied trace file).
- dSYM UUID is checked against the binary UUID separately. A stale dSYM is a
  different bug than a rebuilt binary, and the snapshot alone doesn't catch
  it.
- `atos` failure yields the hex address, never a guessed symbol.

## Requirements

- macOS with the Xcode Command Line Tools (`xcode-select --install`).
- Python 3.10+.
- Terminal (or whichever app launches this server) needs Developer Tools
  access under **System Settings > Privacy & Security > Developer Tools** —
  `vmmap`, `sample`, and any `lldb` attach or launch all go through the same
  permission check.
- Attaching to a running process (`open_session`, or the lazy attach behind
  `debug()`/`backtrace_all()`) requires the target to carry the
  `get-task-allow` entitlement — true for local Debug builds, not for a
  codesigned Release build. `launch_session` isn't affected by this, since
  it starts the process itself.

## Install

```sh
cd natprof-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Register with Claude Code

```sh
claude mcp add natprof -- /Users/roninxv/projects/natprof-mcp/.venv/bin/natprof-mcp
```

(Or point it at `.venv/bin/python -m natprof_mcp.server` if you'd rather not
rely on the console-script entry point.)

## Sessions

Every tool operates on a `session_id` returned by one of two entry points:

- **`open_session(pid, ...)`** attaches to a process that's already running.
- **`launch_session(path, ...)`** starts a fresh process under LLDB — the
  only way to set environment variables (like `MallocStackLogging`) before
  the target's first instruction runs.

Neither attaches LLDB eagerly by default: an attach is a hard freeze of the
whole process, so a profiling-only session shouldn't pay for it unless
asked to. `debug()` and `backtrace_all()` attach lazily on first use
instead; pass `open_session(..., attach_debugger=True)` if you want it up
front.

## Tools

| Tool | Purpose |
|---|---|
| `open_session(pid, dsym_paths=[], attach_debugger=False)` | Attach to a running process: snapshot images, capture UUIDs. |
| `launch_session(path, args=[], env={}, cwd=None, dsym_paths=[], mem_debug=False, stop_at_entry=False)` | Launch a fresh binary under LLDB. `mem_debug=True` sets `MallocStackLogging` for real leak backtraces. |
| `debug(session_id, command)` | Run any LLDB command (`bt`, `expr`, `breakpoint set`, ...). |
| `backtrace_all(session_id)` | Interrupt, dump every thread's backtrace, resume — halts the process for the duration. |
| `light_backtrace(session_id, seconds=1)` | Low-impact "what's every thread doing" snapshot via `sample`, without halting the process. |
| `record(session_id, seconds=10, interval_ms=1)` | Start a stack-sampling profile via `sample`, in the background. Returns immediately with `status: "recording"`. |
| `record_status(session_id)` | Poll a `record()` in progress — `"running"` or `"done"`. |
| `hotspots(session_id, top_n=20, include_system=False)` | Symbolicated self-time leaders from the last completed `record()`. Errors if a recording is still in progress. |
| `set_baseline(session_id)` / `compare(session_id, threshold_pct=1.0)` | Snapshot hotspots, then diff a later run against it. |
| `leaks(session_id)` | Run `leaks --list` against the pid. |
| `verify(session_id)` | Re-check every snapshot's UUID and dSYM match. |
| `close_session(session_id, kill=False)` | Tear down the session. Doesn't kill the process by default — a kill tears down CoreAudio's connection abruptly and pops audio, so the process is just left running (detached) unless you pass `kill=True`. |

## Leak backtraces

`leaks()` only returns allocation backtraces — not just a count — if
`MallocStackLogging` was set before the target launched, and that can't be
turned on retroactively on an already-running process. Use
`launch_session(path, ..., mem_debug=True)` instead of `open_session` to get
them.
