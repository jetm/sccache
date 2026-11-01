#!/usr/bin/env python3
"""Cluster-level smoke checks for the carry-deployed-defects fixes.

Builds sccache and sccache-dist from this checkout plus a stock v0.19.0
sccache-dist, starts schedulers and build servers on 127.0.0.1 in isolated
directories, and checks against real processes:

  (a) a v0.19.0 build server (five-field heartbeat) registers with the new
      scheduler and stays listed, with no error response in the scheduler log;
  (b) a compile that takes 240 s is still in progress at t=200 s and t=230 s
      and exits 0, on a current server and on the v0.19.0 server;
  (c) an upload that does not hash to its archive id answers CannotCache and
      evicts nothing;
  (d) a server SIGKILLed mid-upload holds no entry for the partial file after
      a restart;
  (e) with `[dist] fallback = false`, a remote compile that exits 0 without
      its output fails the client, naming the output, with no local compile
      and nothing cached;
  (f) a Rust rlib compile ships a dependency rlib trimmed to its metadata
      members and an object-only rlib byte for byte, and the dependent crate
      compiles remotely.

The build servers run unprivileged: the overlay builder insists on uid 0, so
each server runs under `unshare -Ur` (root in a user namespace, host network).
`bwrap_path` points at a wrapper that copies a job's unpacked inputs (the
overlay upper directory) aside before exec'ing the real bwrap, which is how (f)
sees exactly what the client shipped.

Usage: smoke_carry_deployed_defects.py [--scenarios a,b,c,d,e,f]
Set SMOKE_KEEP_LOGS=1 to copy the logs to /var/tmp/claude-code/sccache before
the scratch root is removed.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import http.client
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import time

spec = importlib.util.spec_from_file_location(
    "smoke_lib", pathlib.Path("~/.claude/skills/ds-archive/scripts/smoke_lib.py").expanduser()
)
smoke_lib = importlib.util.module_from_spec(spec)
sys.modules["smoke_lib"] = smoke_lib  # dataclasses resolves its module here; omitted, import fails on 3.14
spec.loader.exec_module(smoke_lib)

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRATCH_BASE = pathlib.Path("/var/tmp/claude-code/sccache")
NEW_TARGET = SCRATCH_BASE / "2026-10-31-carry-target"
OLD_TAG = "v0.19.0"
REAL_GCC = "/usr/bin/gcc"
REAL_BWRAP = "/usr/bin/bwrap"
CLIENT_TOKEN = "smoke-client-token"
SERVER_TOKEN = "smoke-server-token"
SLOW_SECONDS = 240
EXPECTED_CHECKS = 17

MANUAL_STEPS = [
    smoke_lib.ManualStep(
        "human",
        "Eviction reuse (task 1.2): with toolchain_cache_size fitting one archive and SCCACHE_LOG=trace on "
        "the build server, run a compile for toolchain B while the eviction of multi-GB toolchain C is still "
        "deleting, then a second compile for toolchain A; the log must show 'Creating toolchain directory for "
        "<A id>' exactly once and A's directory must stay on disk.",
    ),
    smoke_lib.ManualStep(
        "loaded-state",
        "Deployment (task 1.3): compare `pacman -Q sccache-jetm` on pc1, pc2 and pc3 and the recipe pin in "
        "aur-packages with the carry-cleanups tip; no host may run a build that predates 65a8bfef while the "
        "fixes are reported as deployed.",
    ),
]

GCC_WRAPPER_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Passes preprocessing and probes straight to the real gcc. A compile (-c
 * without -E) is logged to LOGPATH, a host path that does not exist inside the
 * build sandbox, so the log records only compiles that ran locally. Only a
 * compile writing a .o sleeps or drops it: sccache's compiler detection runs
 * its own -c probes (one asks the assembler for its version), and those must
 * stay fast. */
int main(int argc, char **argv) {
    int compile = 0, preprocess = 0;
    const char *out = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-c")) compile = 1;
        else if (!strcmp(argv[i], "-E")) preprocess = 1;
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[i + 1];
    }
    argv[0] = REAL_GCC;
    if (!compile || preprocess) {
        execv(REAL_GCC, argv);
        return 127;
    }
    FILE *log = fopen(LOGPATH, "a");
    if (log) {
        for (int i = 0; i < argc; i++) fprintf(log, "%s%s", i ? " " : "", argv[i]);
        fputc('\n', log);
        fclose(log);
    }
    size_t out_len = out ? strlen(out) : 0;
    if (out_len < 3 || strcmp(out + out_len - 2, ".o") != 0) {
        execv(REAL_GCC, argv);
        return 127;
    }
#ifdef SLEEP_S
    unsigned left = SLEEP_S;
    while ((left = sleep(left)) != 0) {
    }
#endif
#ifdef DROP_OUTPUT
    pid_t pid = fork();
    if (pid == 0) {
        execv(REAL_GCC, argv);
        _exit(127);
    }
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) < 0) return 126;
    if (!WIFEXITED(status)) return 125;
    if (WEXITSTATUS(status) != 0) return WEXITSTATUS(status);
    unlink(out);
    return 0;
#else
    execv(REAL_GCC, argv);
    return 127;
#endif
}
"""

BWRAP_WRAPPER = """#!/bin/bash
# Snapshot the job's unpacked inputs (the overlay upper dir beside the bound
# target) before running the real bubblewrap.
if [ "${{1:-}}" != "--version" ]; then
    prev=""
    target=""
    for a in "$@"; do
        if [ "$prev" = "--bind" ]; then target="$a"; break; fi
        prev="$a"
    done
    if [ -n "$target" ]; then
        snap=$(mktemp -d "{snapdir}/job.XXXXXX")
        cp -a "$(dirname "$target")/upper" "$snap/" 2>"$snap/cp.err"
    fi
fi
exec {real_bwrap} "$@"
"""


# ---------------------------------------------------------------- processes


class Proc:
    """A subprocess in its own session, output to a file; only its group is signalled."""

    def __init__(self, name: str, cmd: list[str], env: dict[str, str], cwd: pathlib.Path, log: pathlib.Path):
        self.name = name
        self.log = log
        self._fh = log.open("ab")
        self.popen = subprocess.Popen(
            cmd,
            env=env,
            cwd=cwd,
            stdout=self._fh,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    def signal(self, sig: int) -> None:
        if self.popen.poll() is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            if os.getpgid(self.popen.pid) == self.popen.pid:
                os.killpg(self.popen.pid, sig)

    def stop(self, timeout: float = 15) -> None:
        self.signal(signal.SIGTERM)
        try:
            self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.signal(signal.SIGKILL)
            self.popen.wait()
        self._fh.close()

    def wait(self, timeout: float) -> int | None:
        try:
            return self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def text(self) -> str:
        if not self._fh.closed:
            self._fh.flush()
        return self.log.read_text(errors="replace")


def run(
    cmd: list[str], env: dict[str, str], cwd: pathlib.Path, log: pathlib.Path, timeout: float
) -> tuple[int | None, str]:
    """Run to completion in its own session; return (exit code or None on timeout, output)."""
    proc = Proc(log.stem, cmd, env, cwd, log)
    rc = proc.wait(timeout)
    if rc is None:
        proc.signal(signal.SIGKILL)
        proc.popen.wait()
    proc._fh.close()
    return rc, log.read_text(errors="replace")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout: float, what: str, interval: float = 0.5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise RuntimeError(f"timed out after {timeout:.0f}s waiting for {what}")


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def tail(text: str, n: int = 12) -> str:
    return " | ".join(text.strip().splitlines()[-n:])


# ---------------------------------------------------------------- cluster pieces


class Cluster:
    """One scheduler, one build server and one sccache client daemon."""

    def __init__(
        self,
        name: str,
        root: pathlib.Path,
        base_env: dict[str, str],
        *,
        dist_bin: pathlib.Path,
        server_bin: pathlib.Path,
        client_bin: pathlib.Path,
        cache_size: int,
        bwrap: str,
        toolchains: list[tuple[pathlib.Path, pathlib.Path]],
    ):
        self.name = name
        self.dir = root / name
        for sub in ("cache", "build", "client-dist", "client-cache", "logs"):
            (self.dir / sub).mkdir(parents=True)
        self.dist_bin = dist_bin
        self.server_bin = server_bin
        self.client_bin = client_bin
        self.sched_port = free_port()
        self.server_port = free_port()
        self.client_port = free_port()
        self.server_id = f"127.0.0.1:{self.server_port}"
        self.procs: list[Proc] = []
        self.server: Proc | None = None
        self.server_starts = 0

        (self.dir / "scheduler.conf").write_text(
            f'public_addr = "127.0.0.1:{self.sched_port}"\n'
            f'[client_auth]\ntype = "token"\ntoken = "{CLIENT_TOKEN}"\n'
            f'[server_auth]\ntype = "token"\ntoken = "{SERVER_TOKEN}"\n'
        )
        (self.dir / "server.conf").write_text(
            f'cache_dir = "{self.dir / "cache"}"\n'
            f'public_addr = "{self.server_id}"\n'
            f'scheduler_url = "http://127.0.0.1:{self.sched_port}"\n'
            f"toolchain_cache_size = {cache_size}\n"
            f'[builder]\ntype = "overlay"\nbuild_dir = "{self.dir / "build"}"\nbwrap_path = "{bwrap}"\n'
            f'[scheduler_auth]\ntype = "token"\ntoken = "{SERVER_TOKEN}"\n'
        )
        client_conf = (
            f'[dist]\nscheduler_url = "http://127.0.0.1:{self.sched_port}"\n'
            f'cache_dir = "{self.dir / "client-dist"}"\nfallback = false\n'
            f'[dist.auth]\ntype = "token"\ntoken = "{CLIENT_TOKEN}"\n'
        )
        for local, archive in toolchains:
            client_conf += (
                f'[[dist.toolchains]]\ntype = "path_override"\ncompiler_executable = "{local}"\n'
                f'archive = "{archive}"\narchive_compiler_executable = "/opt/smoke/gcc"\n'
            )
        (self.dir / "client.conf").write_text(client_conf)

        self.env = dict(base_env)
        for var in ("RUSTC_WRAPPER", "SCCACHE_LOG", "SCCACHE_ERROR_LOG", "SCCACHE_CONF", "SCCACHE_DIR"):
            self.env.pop(var, None)
        self.env.update(
            SCCACHE_CONF=str(self.dir / "client.conf"),
            SCCACHE_DIR=str(self.dir / "client-cache"),
            SCCACHE_SERVER_PORT=str(self.client_port),
            SCCACHE_IDLE_TIMEOUT="0",
            SCCACHE_NO_DAEMON="1",
        )

    def log(self, name: str) -> pathlib.Path:
        return self.dir / "logs" / f"{name}.log"

    def start(self) -> None:
        env = dict(self.env, SCCACHE_LOG="debug")
        self.scheduler = self._spawn(
            "scheduler", [str(self.dist_bin), "scheduler", "--config", str(self.dir / "scheduler.conf")], env
        )
        wait_for(lambda: port_open(self.sched_port), 30, f"{self.name} scheduler port")
        self.start_server()
        client_env = dict(self.env, SCCACHE_LOG="debug", SCCACHE_START_SERVER="1")
        self.client = self._spawn("client", [str(self.client_bin)], client_env)
        wait_for(lambda: port_open(self.client_port), 60, f"{self.name} client daemon port")

    def start_server(self) -> None:
        self.server_starts += 1
        env = dict(self.env, SCCACHE_LOG="debug")
        log_name = f"server-{self.server_starts}"
        self.server = self._spawn(
            log_name, ["unshare", "-Ur", str(self.server_bin), "server", "--config", str(self.dir / "server.conf")], env
        )
        server = self.server

        def connected() -> bool:
            if server.popen.poll() is not None:
                raise RuntimeError(f"{self.name} build server exited: {tail(server.text())}")
            return "Server connected to scheduler" in server.text()

        wait_for(connected, 60, f"{self.name} build server registration")

    def _spawn(self, name: str, cmd: list[str], env: dict[str, str]) -> Proc:
        proc = Proc(name, cmd, env, self.dir, self.log(name))
        self.procs.append(proc)
        return proc

    def stop(self) -> None:
        for proc in reversed(self.procs):
            proc.stop()

    def sccache(self, args: list[str], name: str, cwd: pathlib.Path, timeout: float = 120) -> tuple[int | None, str]:
        return run([str(self.client_bin), *args], self.env, cwd, self.log(name), timeout)

    def status(self) -> dict:
        rc, out = self.sccache(["--dist-status"], f"dist-status-{time.monotonic_ns()}", self.dir, 30)
        line = next((ln for ln in out.splitlines() if ln.startswith("{")), None)
        if rc != 0 or line is None:
            raise RuntimeError(f"--dist-status failed (rc={rc}): {tail(out)}")
        return json.loads(line)["SchedulerStatus"][1]

    def stats(self) -> dict:
        rc, out = self.sccache(["--show-stats", "--stats-format", "json"], f"stats-{time.monotonic_ns()}", self.dir, 30)
        line = next((ln for ln in out.splitlines() if ln.startswith("{")), None)
        if rc != 0 or line is None:
            raise RuntimeError(f"--show-stats failed (rc={rc}): {tail(out)}")
        return json.loads(line)["stats"]

    def tc_dir(self) -> pathlib.Path:
        return self.dir / "cache" / "tc"


def cache_entries(tc_dir: pathlib.Path) -> dict[str, int]:
    return {p.relative_to(tc_dir).as_posix(): p.stat().st_size for p in tc_dir.rglob("*") if p.is_file()}


# ---------------------------------------------------------------- dist protocol by hand


def alloc_job(cluster: Cluster, archive_id: str) -> dict:
    body = struct.pack("<Q", len(archive_id)) + archive_id.encode()
    conn = http.client.HTTPConnection("127.0.0.1", cluster.sched_port, timeout=60)
    try:
        conn.request(
            "POST",
            "/api/v1/scheduler/alloc_job",
            body=body,
            headers={
                "Authorization": f"Bearer {CLIENT_TOKEN}",
                "Content-Type": "application/octet-stream",
                "Accept": "application/json",
            },
        )
        resp = conn.getresponse()
        data = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        raise RuntimeError(f"alloc_job answered {resp.status}: {data[:300]!r}")
    result = json.loads(data)
    if "Success" not in result:
        raise RuntimeError(f"alloc_job failed: {result}")
    return result["Success"]


def server_connection(cluster: Cluster) -> http.client.HTTPSConnection:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection("127.0.0.1", cluster.server_port, timeout=120, context=ctx)


def submit_headers(job: dict, length: int) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {job['job_alloc']['auth']}",
        "Content-Type": "application/octet-stream",
        "Accept": "application/json",
        "Content-Length": str(length),
    }


# ---------------------------------------------------------------- setup


def build_binaries(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    env = dict(os.environ, CARGO_TARGET_DIR=str(NEW_TARGET))
    rc, out = run(["cargo", "build", "--features", "all,dist-server"], env, REPO, root / "build-new.log", 3600)
    if rc != 0:
        raise RuntimeError(f"cargo build of {REPO} failed (rc={rc}): {tail(out)}")

    old_src = root / "v019-src"
    old_src.mkdir()
    rc, out = run(
        ["git", "-C", str(REPO), "archive", "-o", str(root / "v019.tar"), OLD_TAG],
        dict(os.environ),
        root,
        root / "git-archive.log",
        120,
    )
    if rc != 0:
        raise RuntimeError(f"git archive {OLD_TAG} failed: {tail(out)}")
    with tarfile.open(root / "v019.tar") as tf:
        tf.extractall(old_src, filter="data")
    env = dict(os.environ, CARGO_TARGET_DIR=str(root / "v019-target"))
    rc, out = run(["cargo", "build", "--features", "dist-server"], env, old_src, root / "build-old.log", 3600)
    if rc != 0:
        raise RuntimeError(f"cargo build of {OLD_TAG} failed (rc={rc}): {tail(out)}")
    return (
        NEW_TARGET / "debug" / "sccache",
        NEW_TARGET / "debug" / "sccache-dist",
        root / "v019-target" / "debug" / "sccache-dist",
    )


def build_wrapper(root: pathlib.Path, mode: str, defines: list[str]) -> pathlib.Path:
    src = root / "gccwrap.c"
    if not src.exists():
        src.write_text(GCC_WRAPPER_C)
    out = root / "bin" / mode / "gcc"
    out.parent.mkdir(parents=True)
    log_path = root / "wraplog" / f"{mode}.log"
    cmd = [REAL_GCC, "-O1", "-o", str(out), str(src), f'-DREAL_GCC="{REAL_GCC}"', f'-DLOGPATH="{log_path}"', *defines]
    rc, text = run(cmd, dict(os.environ), root, root / f"wrapper-{mode}.log", 120)
    if rc != 0:
        raise RuntimeError(f"building the {mode} gcc wrapper failed: {tail(text)}")
    return out


def wrapper_archive(base: pathlib.Path, wrapper: pathlib.Path, out: pathlib.Path) -> None:
    """The packaged gcc toolchain plus the wrapper at /opt/smoke/gcc."""
    with tarfile.open(base, "r:gz") as src, tarfile.open(out, "w:gz", compresslevel=1) as dst:
        for member in src:
            dst.addfile(member, src.extractfile(member) if member.isfile() else None)
        info = tarfile.TarInfo("opt/smoke/gcc")
        info.size = wrapper.stat().st_size
        info.mode = 0o755
        info.mtime = int(time.time())
        with wrapper.open("rb") as fh:
            dst.addfile(info, fh)


def wrapper_compiles(root: pathlib.Path, mode: str, source: str) -> list[str]:
    """Local `-c` runs of the wrapper that compiled ``source`` (sccache's own -c probes do not count)."""
    log = root / "wraplog" / f"{mode}.log"
    lines = log.read_text().splitlines() if log.exists() else []
    return [ln for ln in lines if source in ln.split()]


# ---------------------------------------------------------------- scenarios


def scenario_ab(run_: smoke_lib.SmokeRun, root: pathlib.Path, new: Cluster, legacy: Cluster) -> None:
    status = legacy.status()
    listed = [s["id"] for s in status.get("servers", [])]
    run_.check(
        "(a) a v0.19.0 build server registers with the new scheduler and --dist-status lists it",
        legacy.server_id in listed and status["num_servers"] == 1,
        f"listed={listed} status={status}",
    )

    work = root / "work"
    work.mkdir(exist_ok=True)
    for c in (new, legacy):
        (work / f"slow-{c.name}.c").write_text(f"int slow_{c.name.replace('-', '_')}(int x) {{ return x + 1; }}\n")
    slow_gcc = root / "bin" / "slow" / "gcc"
    started = time.monotonic()
    compiles = {
        c.name: Proc(
            f"slow-compile-{c.name}",
            [str(c.client_bin), str(slow_gcc), "-c", f"slow-{c.name}.c", "-o", f"slow-{c.name}.o"],
            c.env,
            work,
            c.log("slow-compile"),
        )
        for c in (new, legacy)
    }
    samples: dict[str, dict[int, object]] = {new.name: {}, legacy.name: {}}
    try:
        for mark in (200, 230):
            time.sleep(max(0.0, started + mark - time.monotonic()))
            for c in (new, legacy):
                try:
                    samples[c.name][mark] = c.status()
                except RuntimeError as exc:
                    samples[c.name][mark] = str(exc)
        rcs = {
            name: p.wait(timeout=max(30.0, started + SLOW_SECONDS + 180 - time.monotonic()))
            for name, p in compiles.items()
        }
    finally:
        for p in compiles.values():
            p.stop()
    elapsed = time.monotonic() - started

    for label, c in (("(b)", new), ("(b, v0.19.0 server)", legacy)):
        for mark in (200, 230):
            s = samples[c.name][mark]
            ok = (
                isinstance(s, dict)
                and s["in_progress"] == 1
                and any(srv["id"] == c.server_id and srv["in_progress"] == 1 for srv in s.get("servers", []))
            )
            run_.check(f"{label} a 240 s distributed compile is still in_progress at t={mark}s", ok, f"status={s}")
        stats = c.stats()
        local = wrapper_compiles(root, "slow", f"slow-{c.name}.c")
        rc = rcs[c.name]
        ok = (
            rc == 0
            and (work / f"slow-{c.name}.o").is_file()
            and stats["dist_compiles"].get(c.server_id) == 1
            and stats["dist_errors"] == 0
            and not local
        )
        run_.check(
            f"{label} the 240 s compile ran on the build server and exits 0",
            ok,
            f"rc={rc} elapsed={elapsed:.0f}s dist_compiles={stats['dist_compiles']} dist_errors={stats['dist_errors']} "
            f"local wrapper compiles={local} output: {tail(compiles[c.name].text())}",
        )

    status = legacy.status()
    listed = [s["id"] for s in status.get("servers", [])]
    sched_errors = re.findall(r".*Res \d+ error.*", legacy.scheduler.text())
    hb_errors = re.findall(r".*Failed to send heartbeat.*", legacy.server.text())
    run_.check(
        "(a) after 4+ minutes of heartbeats the v0.19.0 server is still listed and no request was refused",
        legacy.server_id in listed and not sched_errors and not hb_errors,
        f"listed={listed} scheduler errors={sched_errors[:3]} heartbeat errors={hb_errors[:3]}",
    )


def scenario_e(run_: smoke_lib.SmokeRun, root: pathlib.Path, new: Cluster) -> None:
    work = root / "work"
    work.mkdir(exist_ok=True)
    (work / "drop.c").write_text("int dropped(int x) { return x * 7; }\n")
    rc, _ = new.sccache(["--zero-stats"], "zero-stats-e", work, 30)
    if rc != 0:
        raise RuntimeError("--zero-stats failed")
    drop_gcc = root / "bin" / "drop" / "gcc"
    rc, out = new.sccache([str(drop_gcc), "-c", "drop.c", "-o", "drop.o"], "drop-compile", work, 300)
    stats = new.stats()
    run_.check(
        "(e) fallback off: a remote compile that drops its output fails the client, naming the output",
        rc not in (0, None) and "drop.o" in out,
        f"rc={rc} output: {tail(out)}",
    )
    local = wrapper_compiles(root, "drop", "drop.c")
    run_.check(
        "(e) fallback off: no local compile ran and nothing was cached",
        not local and stats["cache_writes"] == 0 and not (work / "drop.o").exists(),
        f"local wrapper compiles={local} cache_writes={stats['cache_writes']} "
        f"drop.o exists={(work / 'drop.o').exists()} dist_compiles={stats['dist_compiles']}",
    )


def scenario_c(run_: smoke_lib.SmokeRun, new: Cluster, capacity: int) -> None:
    before = cache_entries(new.tc_dir())
    used = sum(before.values())
    if not before:
        raise RuntimeError("the build server caches no toolchain yet; (c) needs one to protect")
    forged_size = capacity - used // 2  # more than the free space, within the capacity
    archive_id = secrets.token_hex(32)
    job = alloc_job(new, archive_id)
    if not job["need_toolchain"]:
        raise RuntimeError(f"server already holds random toolchain {archive_id}")
    body = (b"not the archive this id names\n" * (forged_size // 30 + 1))[:forged_size]
    conn = server_connection(new)
    try:
        conn.request(
            "POST",
            f"/api/v1/distserver/submit_toolchain/{job['job_alloc']['job_id']}",
            body=body,
            headers=submit_headers(job, len(body)),
        )
        resp = conn.getresponse()
        answer = resp.read().decode(errors="replace")
    finally:
        conn.close()
    rejected = f"Rejected toolchain upload for {archive_id}" in new.server.text()
    run_.check(
        "(c) an upload that does not hash to its archive id answers CannotCache",
        resp.status == 200 and json.loads(answer) == "CannotCache" and rejected,
        f"status={resp.status} body={answer[:200]} rejection logged={rejected}",
    )
    after = cache_entries(new.tc_dir())
    run_.check(
        "(c) the forged upload evicted no cached toolchain and left no file behind",
        after == before,
        f"forged {forged_size} bytes into capacity {capacity} with {used} used; before={before} after={after}",
    )


def scenario_d(run_: smoke_lib.SmokeRun, new: Cluster) -> None:
    before = cache_entries(new.tc_dir())
    job = alloc_job(new, secrets.token_hex(32))
    total = 64 * 1024 * 1024
    chunk = b"\x5a" * (8 * 1024 * 1024)
    conn = server_connection(new)
    partial: list[str] = []
    try:
        conn.putrequest(
            "POST", f"/api/v1/distserver/submit_toolchain/{job['job_alloc']['job_id']}", skip_accept_encoding=True
        )
        for k, v in submit_headers(job, total).items():
            conn.putheader(k, v)
        conn.endheaders()
        conn.send(chunk)

        def partial_on_disk() -> bool:
            partial[:] = [
                p
                for p, size in cache_entries(new.tc_dir()).items()
                if pathlib.PurePosixPath(p).name.startswith(".sccachetmp") and size > 0
            ]
            return bool(partial)

        with contextlib.suppress(RuntimeError):
            wait_for(partial_on_disk, 30, "the partial upload file")
        run_.check(
            "(d) a partial upload file is on disk in the cache while the upload is in flight",
            bool(partial),
            f"cache entries mid-upload={cache_entries(new.tc_dir())}",
        )
        new.server.signal(signal.SIGKILL)
        new.server.popen.wait(timeout=30)
    finally:
        conn.close()
    new.start_server()
    after = cache_entries(new.tc_dir())
    leftovers = [p for p in after if ".sccachetmp" in p]
    run_.check(
        "(d) after SIGKILL mid-upload and a restart the cache holds no entry for the partial file",
        bool(partial) and not leftovers and after == before,
        f"partial={partial} before={before} after={after}",
    )


def scenario_f(run_: smoke_lib.SmokeRun, root: pathlib.Path, rust: Cluster, snapdir: pathlib.Path) -> None:
    rc, out = run(["rustc", "--print", "sysroot"], dict(os.environ), root, root / "rust-sysroot.log", 60)
    if rc != 0:
        raise RuntimeError(f"rustc --print sysroot failed: {tail(out)}")
    rustc = pathlib.Path(out.strip().splitlines()[-1]) / "bin" / "rustc"
    rdir = root / "rust"
    deps = rdir / "deps"
    deps.mkdir(parents=True)
    (rdir / "dep.rs").write_text("pub fn f() -> u32 { 41 }\n")
    (rdir / "user.rs").write_text("pub fn g() -> u32 { dep::f() + 1 }\n")
    (rdir / "objonly.c").write_text("int objonly_symbol(void) { return 5; }\n")
    host_env = dict(os.environ)
    host_env.pop("RUSTC_WRAPPER", None)
    rc, out = run(
        [
            str(rustc),
            "--crate-name",
            "dep",
            "--crate-type",
            "rlib",
            "--edition",
            "2021",
            "-C",
            "extra-filename=-d1e2",
            "--out-dir",
            str(deps),
            "dep.rs",
        ],
        host_env,
        rdir,
        root / "rust-dep.log",
        300,
    )
    if rc != 0:
        raise RuntimeError(f"building libdep.rlib failed: {tail(out)}")
    dep_rlib = deps / "libdep-d1e2.rlib"
    rc, out = run([REAL_GCC, "-c", "objonly.c", "-o", "objonly.o"], host_env, rdir, root / "rust-objonly-cc.log", 60)
    if rc != 0:
        raise RuntimeError(f"compiling objonly.o failed: {tail(out)}")
    obj_rlib = deps / "libobjonly-0b1e.rlib"
    rc, out = run(["ar", "crs", str(obj_rlib), "objonly.o"], host_env, rdir, root / "rust-objonly-ar.log", 60)
    if rc != 0:
        raise RuntimeError(f"ar of libobjonly failed: {tail(out)}")

    def members(path: pathlib.Path, name: str) -> list[str]:
        rc, out = run(["ar", "t", str(path)], host_env, rdir, root / f"ar-t-{name}.log", 60)
        if rc != 0:
            raise RuntimeError(f"ar t {path} failed: {tail(out)}")
        return out.split()

    original_members = members(dep_rlib, "original")
    (rdir / "out").mkdir()
    rc, out = rust.sccache(
        [
            str(rustc),
            "--crate-name",
            "user",
            "--crate-type",
            "rlib",
            "--edition=2021",
            "user.rs",
            "--emit=dep-info,metadata,link",
            "-C",
            "opt-level=0",
            "-C",
            "extra-filename=-u1",
            "--out-dir",
            "out",
            "-L",
            f"dependency={deps}",
            "--extern",
            f"dep={dep_rlib}",
        ],
        "rust-compile",
        rdir,
        900,
    )
    stats = rust.stats()
    run_.check(
        "(f) the dependent crate compiles remotely against the shipped rlibs (fallback off)",
        rc == 0
        and (rdir / "out" / "libuser-u1.rlib").is_file()
        and stats["dist_compiles"].get(rust.server_id) == 1
        and stats["dist_errors"] == 0,
        f"rc={rc} dist_compiles={stats['dist_compiles']} dist_errors={stats['dist_errors']} "
        f"not_cached={stats['not_cached']} output: {tail(out)}",
    )

    def shipped(name: str) -> list[pathlib.Path]:
        return sorted(snapdir.rglob(name))

    shipped_dep = shipped(dep_rlib.name)
    shipped_members = members(shipped_dep[0], "shipped") if len(shipped_dep) == 1 else None
    has_object = any(m.endswith(".o") for m in original_members)
    run_.check(
        "(f) the dependency rlib ships as lib.rmeta and lib.rmeta-link only",
        has_object and shipped_members == ["lib.rmeta", "lib.rmeta-link"],
        f"original members={original_members} shipped copies={shipped_dep} shipped members={shipped_members}",
    )
    shipped_obj = shipped(obj_rlib.name)
    run_.check(
        "(f) an object-only rlib ships byte for byte",
        len(shipped_obj) == 1 and shipped_obj[0].read_bytes() == obj_rlib.read_bytes(),
        f"shipped copies={shipped_obj} original size={obj_rlib.stat().st_size} "
        f"shipped size={shipped_obj[0].stat().st_size if shipped_obj else None}",
    )


# ---------------------------------------------------------------- main


def make_removable(root: pathlib.Path) -> None:
    """Overlay work dirs come back mode 000; open everything up so rmtree can remove it."""
    for dirpath, dirnames, _ in os.walk(root, topdown=True, onerror=None):
        for d in dirnames:
            p = pathlib.Path(dirpath) / d
            with contextlib.suppress(OSError):
                if not p.is_symlink():
                    p.chmod(p.stat().st_mode | stat.S_IRWXU)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenarios", default="a,b,c,d,e,f")
    wanted = set(parser.parse_args().scenarios.split(","))
    today = datetime.date.today().isoformat()
    SCRATCH_BASE.mkdir(parents=True, exist_ok=True)

    with (
        smoke_lib.SmokeRun(expected=EXPECTED_CHECKS, manual_steps=MANUAL_STEPS) as run_,
        smoke_lib.isolated_env(str(SCRATCH_BASE / f"{today}-smoke-")) as (root, env),
    ):
        clusters: list[Cluster] = []
        try:
            print(f"scratch root: {root}")
            client_bin, dist_bin, old_dist_bin = build_binaries(root)
            print(f"built {client_bin}, {dist_bin} and {OLD_TAG} {old_dist_bin}")

            (root / "wraplog").mkdir()
            slow = build_wrapper(root, "slow", [f"-DSLEEP_S={SLOW_SECONDS}"])
            drop = build_wrapper(root, "drop", ["-DDROP_OUTPUT"])
            rc, out = run(
                [str(client_bin), "--package-toolchain", REAL_GCC, str(root / "gcc-base.tar.gz")],
                dict(env, SCCACHE_CONF=str(root / "none.conf")),
                root,
                root / "package-toolchain.log",
                300,
            )
            if rc != 0:
                raise RuntimeError(f"--package-toolchain failed: {tail(out)}")
            slow_tc, drop_tc = root / "tc-slow.tar.gz", root / "tc-drop.tar.gz"
            wrapper_archive(root / "gcc-base.tar.gz", slow, slow_tc)
            wrapper_archive(root / "gcc-base.tar.gz", drop, drop_tc)

            snapdir = root / "snapshots"
            snapdir.mkdir()
            bwrap = root / "bwrap-snapshot"
            bwrap.write_text(BWRAP_WRAPPER.format(snapdir=snapdir, real_bwrap=REAL_BWRAP))
            bwrap.chmod(0o755)

            # Room for both wrapper toolchains and little else, so a forged upload
            # that were accepted would have to evict one of them.
            capacity = slow_tc.stat().st_size + drop_tc.stat().st_size + 8 * 1024 * 1024
            toolchains = [(slow, slow_tc), (drop, drop_tc)]
            common = dict(client_bin=client_bin, bwrap=str(bwrap), toolchains=toolchains)

            new = legacy = None
            if wanted & {"a", "b", "c", "d", "e"}:
                new = Cluster(
                    "current", root, env, dist_bin=dist_bin, server_bin=dist_bin, cache_size=capacity, **common
                )
                clusters.append(new)
                new.start()
            if wanted & {"a", "b"}:
                legacy = Cluster(
                    "legacy", root, env, dist_bin=dist_bin, server_bin=old_dist_bin, cache_size=10 * 1024**3, **common
                )
                clusters.append(legacy)
                legacy.start()

            scenarios = []
            if wanted & {"a", "b"}:
                scenarios.append(("a+b", lambda: scenario_ab(run_, root, new, legacy)))
            if "e" in wanted:
                scenarios.append(("e", lambda: scenario_e(run_, root, new)))
            if "c" in wanted:
                scenarios.append(("c", lambda: scenario_c(run_, new, capacity)))
            if "d" in wanted:
                scenarios.append(("d", lambda: scenario_d(run_, new)))
            if "f" in wanted:

                def f() -> None:
                    rust = Cluster(
                        "rust",
                        root,
                        env,
                        dist_bin=dist_bin,
                        server_bin=dist_bin,
                        cache_size=10 * 1024**3,
                        client_bin=client_bin,
                        bwrap=str(bwrap),
                        toolchains=[],
                    )
                    clusters.append(rust)
                    rust.start()
                    scenario_f(run_, root, rust, snapdir)

                scenarios.append(("f", f))

            for name, body in scenarios:
                print(f"--- scenario {name}")
                try:
                    body()
                except Exception as exc:  # a broken scenario is reported, the rest still run
                    print(f"SKIP scenario {name}: could not complete - {type(exc).__name__}: {exc}")
        finally:
            for c in clusters:
                c.stop()
            if os.environ.get("SMOKE_KEEP_LOGS"):
                keep = SCRATCH_BASE / f"{today}-smoke-logs-{os.getpid()}"
                for c in clusters:
                    shutil.copytree(c.dir / "logs", keep / c.name, dirs_exist_ok=True)
                print(f"logs kept in {keep}")
            make_removable(root)
        sys.exit(smoke_lib.finish(run_))


if __name__ == "__main__":
    main()
