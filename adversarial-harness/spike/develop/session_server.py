#!/usr/bin/env python3
# Develop-stage session server (develop-stage.md §4). Runs INSIDE the sandbox
# container as one long-lived process, speaking line-delimited JSON on stdin/stdout.
#
# It holds the Interactive Agent Tool state that must persist ACROSS calls (the
# EnIGMA mechanism): a live target process AND a live gdb session, kept open
# together so the model can send bytes, observe crash state, and adjust — the way
# a human exploit developer works — instead of stateless run-once calls.
#
# The Node MCP seam keeps this container (hence this process, hence the state)
# alive for the whole agent session and shuttles JSON commands in. Binary bytes
# cross the boundary hex-encoded.
#
# Ops (each an {"op": "...", ...} line -> one JSON response line):
#   target_start / target_send / target_recv / target_poll   persistent target I/O
#   debug_start / debug_cmd / debug_regs / debug_continue     persistent gdb session
#   cyclic / cyclic_find                                      pattern (offset find)
#   checksec / symbol / gadgets                               exploit-dev primitives
#   exploit                                                   build+verify a payload N times
import os, sys, json, traceback, subprocess, select, time, fcntl

os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")
from pwn import (
    context, process, ELF, cyclic, cyclic_find, ROP,
)
# The spike substrate is ARM64 (Apple Silicon, native — no emulation). The
# ret2win ladder is demonstrated on aarch64: the return address is the saved link
# register (x30) on the stack; overwriting it and letting vuln() return (ret ->
# br x30) redirects control to win(). x86 via --platform emulation is a future option.
context.arch = "aarch64"
context.log_level = "error"

BIN = "/work/ret2win"
S = {"io": None, "gdb": None}
SENT = "<<GDBQ>>"   # unique gdb prompt sentinel; keeps gdb output framed and OFF the protocol stdout


def _set_nonblock(fd):
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def _gdb_read_until_prompt(timeout=15):
    p = S["gdb"]
    fd = p.stdout.fileno()
    buf, end = "", time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 65536).decode("latin1")
            except BlockingIOError:
                continue
            if chunk == "" and p.poll() is not None:
                break
            buf += chunk
            if SENT in buf:
                return buf
    return buf  # timed out; return what we have


def _hex(b):     return (b or b"").hex()
def _unhex(s):   return bytes.fromhex(s) if s else b""


def op_target_start(a):
    if S["io"]:
        try: S["io"].close()
        except Exception: pass
    S["io"] = process([BIN])
    return {"pid": S["io"].pid}

def op_target_send(a):
    S["io"].send(_unhex(a.get("data_hex", "")))
    return {"sent": len(_unhex(a.get("data_hex", "")))}

def op_target_recv(a):
    to = a.get("timeout", 1.0)
    data = S["io"].recv(timeout=to) if S["io"] else b""
    return {"data_hex": _hex(data), "text": (data or b"").decode("latin1")}

def op_target_poll(a):
    io = S["io"]
    if not io: return {"running": False, "exit": None}
    rc = io.poll()
    return {"running": rc is None, "exit": rc}


def op_debug_start(a):
    # Persistent gdb subprocess. gdb's own stdout is captured here (never the
    # protocol channel) and framed by a unique prompt sentinel. State (breakpoints,
    # the inferior, registers) persists across debug_cmd calls -- the IAT property.
    if S["gdb"]:
        try: S["gdb"].kill()
        except Exception: pass
    p = subprocess.Popen(
        ["gdb", "-q", "-nx", BIN],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=0,
    )
    S["gdb"] = p
    _set_nonblock(p.stdout.fileno())
    p.stdin.write(f"set prompt {SENT}\\n\n"); p.stdin.flush()
    _gdb_read_until_prompt()  # consume banner + first (old) prompt
    for cmd in a.get("init", []):
        p.stdin.write(cmd + "\n"); p.stdin.flush(); _gdb_read_until_prompt()
    return {"started": True, "pid": p.pid}

def _ensure_gdb():
    # Lazily start the persistent gdb session on first debug use, so the model
    # can call debug/find_offset without an explicit start step.
    if S["gdb"] is None or S["gdb"].poll() is not None:
        op_debug_start({})

def _gdb_cmd(cmd, timeout=15):
    _ensure_gdb()
    p = S["gdb"]
    p.stdin.write(cmd + "\n"); p.stdin.flush()
    out = _gdb_read_until_prompt(timeout)
    return out.replace(SENT, "").strip()

def op_debug_cmd(a):
    return {"output": _gdb_cmd(a["cmd"], a.get("timeout", 15))}

def op_debug_regs(a):
    # aarch64: pc (control), sp, x30 (link register / saved return), x0/x1 (args)
    return {"registers": _gdb_cmd("info registers pc sp x29 x30 x0 x1")}

def op_crash_offset(a):
    # Debugger-driven offset discovery: run a cyclic pattern under gdb, let the
    # function return into it, read the faulting pc, and map it back to an offset.
    # This is the persistent-debugger IAT doing real exploit-dev work.
    n = int(a.get("length", 200))
    patt = cyclic(n)
    with open("/tmp/gdb_input", "wb") as f:
        f.write(patt)
    _gdb_cmd("delete")                  # clear breakpoints so run goes straight to the crash
    _gdb_cmd("run < /tmp/gdb_input")    # runs to the fault (return into the pattern)
    pcline = _gdb_cmd("info registers pc")
    import re as _re
    m = _re.search(r"pc\s+0x([0-9a-f]+)", pcline)
    if not m:
        return {"error": "no pc after run", "raw": pcline}
    pc = int(m.group(1), 16)
    # the low bytes of pc are the cyclic subsequence that landed in the return slot
    val = (pc & 0xffffffffffffffff).to_bytes(8, "little").rstrip(b"\x00")[:4]
    try:
        off = cyclic_find(val)
    except Exception as e:
        off = -1
    return {"pc": hex(pc), "offset": off}

def op_debug_run_input(a):
    # Write bytes to a file inside the sandbox and `run < file` under gdb, so a
    # crash can be inspected (e.g. read $rip after a stack-smash). Coexists with
    # the live gdb session: breakpoints set earlier still apply.
    data = _unhex(a.get("data_hex", ""))
    with open("/tmp/gdb_input", "wb") as f:
        f.write(data)
    return {"output": _gdb_cmd("run < /tmp/gdb_input", a.get("timeout", 20))}


def op_cyclic(a):
    n = int(a.get("length", 128))
    return {"pattern_hex": _hex(cyclic(n))}

def op_cyclic_find(a):
    # value may be a hex-encoded 8-byte dword/qword substring or an int
    v = a.get("value")
    if isinstance(v, str):
        v = _unhex(v)
    return {"offset": cyclic_find(v)}


def op_checksec(a):
    e = ELF(BIN, checksec=False)
    return {
        "arch": e.arch, "bits": e.bits, "pie": e.pie, "nx": e.nx,
        "canary": e.canary, "relro": e.relro,
        "symbols": {k: hex(v) for k, v in e.symbols.items() if k in ("win", "vuln", "main")},
    }

def op_symbol(a):
    e = ELF(BIN, checksec=False)
    name = a["name"]
    if name not in e.symbols:
        return {"error": f"no symbol {name}"}
    return {"name": name, "addr": e.symbols[name], "addr_hex": hex(e.symbols[name])}

def op_gadgets(a):
    e = ELF(BIN, checksec=False)
    rop = ROP(e)
    q = a.get("query", "ret")
    found = {}
    for g in ("ret", "pop rdi", "pop rsi", "pop rax", "syscall"):
        try:
            addr = rop.find_gadget(g.split())
            if addr: found[g] = hex(addr[0] if hasattr(addr, "__getitem__") else addr.address)
        except Exception:
            pass
    return {"gadgets": found}


def op_exploit(a):
    # Build+verify: send a payload to a FRESH process N times; the objective is
    # the marker file /tmp/objective_marker being written by win().
    payload = _unhex(a["payload_hex"])
    times = int(a.get("times", 1))
    marker_env = a.get("marker", "")
    fires, results = 0, []
    for _ in range(times):
        try: os.remove("/tmp/objective_marker")
        except FileNotFoundError: pass
        env = dict(os.environ)
        if marker_env: env["AEGIS_MARKER"] = marker_env
        io = process([BIN], env=env)
        try:
            io.send(payload)
            rc = io.wait(timeout=5)
        except Exception:
            rc = None
        finally:
            try: io.close()
            except Exception: pass
        fired = os.path.exists("/tmp/objective_marker")
        content = ""
        if fired:
            with open("/tmp/objective_marker") as f: content = f.read()
        fires += 1 if fired else 0
        results.append({"exit": rc, "marker_fired": fired, "marker_content": content})
    return {"times": times, "fires": fires, "reliability": fires / times if times else 0, "results": results}


OPS = {k[3:]: v for k, v in globals().items() if k.startswith("op_")}


def main():
    sys.stdout.write(json.dumps({"ready": True, "ops": sorted(OPS)}) + "\n")
    sys.stdout.flush()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            op = req.get("op")
            if op not in OPS:
                resp = {"ok": False, "error": f"unknown op {op}"}
            else:
                resp = {"ok": True, **(OPS[op](req) or {})}
        except Exception as e:
            resp = {"ok": False, "error": str(e), "trace": traceback.format_exc().splitlines()[-3:]}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
