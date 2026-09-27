#!/usr/bin/env python3
"""Runs the v2 control re-run and the v3 run end to end, one step after another.

Steps (each logs to outputs/logs/<step>.log; progress in outputs/logs/v3_pipeline_status.json):

  tests       pytest tests/ -- the pipeline stops here if anything fails on this machine
  v2_rerun    run_comparison_benchmark.py --query-set v2 --log-ties  -> outputs/reports/v2_rerun
  v2_compare  compare_runs.py: every point metric and top-5 list of the re-run vs outputs/reports/v2
  v3          run_comparison_benchmark.py --query-set v3 --log-ties  -> outputs/reports/v3
  v3_sweep    run_bridge_sweep.py --query-set v3, grid around the corrected threshold
  v3_ties     tie_audit.py --sweep-only --query-set v3 (tie-aware sweep)
  v3_report   regenerate_report.py + audit_checks.py on outputs/reports/v3, now with the sweep
  v3_mcnemar  mcnemar_restricted.py on outputs/reports/v3

The archived run in outputs/reports/v2 is only ever read. While the pipeline runs, Windows is
asked not to go to sleep (SetThreadExecutionState, released when the process exits; the display
may still turn off).

Usage:
  python scripts/run_v3_pipeline.py                 # everything
  python scripts/run_v3_pipeline.py --from v3       # resume at a step
  python scripts/run_v3_pipeline.py --only v3_report v3_mcnemar
"""
import argparse
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "outputs" / "logs"
STATUS = LOG_DIR / "v3_pipeline_status.json"
ARCHIVED = (ROOT / "outputs" / "reports" / "v2").resolve()

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

BENCH = ["--isolated-targets", "--topological", "--cost-free", "--log-ties"]
SWEEP_GRID = ["10", "20", "40", "80", "100", "120", "140", "146", "147", "150", "160", "320"]

#: (name, argv after the interpreter, output directory the step writes to or None, fatal)
STEPS = [
    ("tests", ["-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], None, True),
    ("v2_rerun", ["scripts/run_comparison_benchmark.py", *BENCH, "--query-set", "v2",
                  "--out-dir", "outputs/reports/v2_rerun"], "outputs/reports/v2_rerun", True),
    ("v2_compare", ["scripts/compare_runs.py", "--a", "outputs/reports/v2",
                    "--b", "outputs/reports/v2_rerun"], "outputs/reports/v2_rerun", False),
    ("v3", ["scripts/run_comparison_benchmark.py", *BENCH, "--query-set", "v3",
            "--out-dir", "outputs/reports/v3"], "outputs/reports/v3", True),
    ("v3_sweep", ["scripts/run_bridge_sweep.py", "--query-set", "v3", "--out-dir", "outputs/reports/v3",
                  "--bridges", *SWEEP_GRID], "outputs/reports/v3", True),
    ("v3_ties", ["scripts/tie_audit.py", "--in-dir", "outputs/reports/v3", "--sweep-only",
                 "--query-set", "v3"], "outputs/reports/v3", True),
    ("v3_report", ["scripts/regenerate_report.py", "--in-dir", "outputs/reports/v3"], "outputs/reports/v3", True),
    ("v3_audit", ["scripts/audit_checks.py", "--in-dir", "outputs/reports/v3"], "outputs/reports/v3", False),
    ("v3_mcnemar", ["scripts/mcnemar_restricted.py", "--in-dir", "outputs/reports/v3"], "outputs/reports/v3", True),
]
NAMES = [s[0] for s in STEPS]


def keep_awake(on: bool):
    """Ask Windows not to sleep while the pipeline runs (no-op elsewhere)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if on else 0)
        ctypes.windll.kernel32.SetThreadExecutionState(flags)
    except Exception as e:  # never fatal
        print(f"[!] Could not change the sleep request: {e}")


def save_status(status):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8")


def run_step(name, argv, status):
    log_path = LOG_DIR / f"{name}.log"
    cmd = [sys.executable, "-u", *argv]
    entry = {"step": name, "cmd": " ".join(argv), "log": str(log_path.relative_to(ROOT)),
             "start": datetime.now().isoformat(timespec="seconds"), "end": None, "returncode": None}
    status["steps"].append(entry)
    status["current"] = name
    save_status(status)
    print(f"\n{'=' * 78}\n[{entry['start']}] STEP {name}: {' '.join(argv)}\n{'=' * 78}", flush=True)
    t0 = time.time()
    env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
    with open(log_path, "w", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1)
        for line in proc.stdout:
            log.write(line)
            log.flush()
            print(line, end="", flush=True)
        rc = proc.wait()
    entry.update(end=datetime.now().isoformat(timespec="seconds"), returncode=rc,
                 minutes=round((time.time() - t0) / 60, 1))
    save_status(status)
    print(f"[{entry['end']}] STEP {name} finished: return code {rc} ({entry['minutes']} min)", flush=True)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--from", dest="start", choices=NAMES, default=None, help="resume at this step")
    ap.add_argument("--only", nargs="+", choices=NAMES, default=None, help="run only these steps")
    args = ap.parse_args()

    selected = NAMES
    if args.start:
        selected = NAMES[NAMES.index(args.start):]
    if args.only:
        selected = [n for n in NAMES if n in args.only]

    for name, argv, out_dir, _ in STEPS:
        if out_dir and (ROOT / out_dir).resolve() == ARCHIVED:
            raise SystemExit(f"Step {name} would write into the archived run {ARCHIVED}; refusing.")

    status = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "python": platform.python_version(), "platform": platform.platform(),
        "executable": sys.executable, "selected": selected, "steps": [], "current": None,
        "finished": None, "result": None,
    }
    save_status(status)
    keep_awake(True)
    result = "ok"
    try:
        for name, argv, _, fatal in STEPS:
            if name not in selected:
                continue
            rc = run_step(name, argv, status)
            if rc != 0 and fatal:
                result = f"stopped: step {name} failed with return code {rc}"
                break
            if rc != 0:
                print(f"[i] Step {name} returned {rc}; this step reports findings, the pipeline goes on.")
    except KeyboardInterrupt:
        result = "interrupted"
    finally:
        keep_awake(False)
        status.update(current=None, finished=datetime.now().isoformat(timespec="seconds"), result=result)
        save_status(status)
    print(f"\nPIPELINE: {result}. Status: {STATUS}")
    return 0 if result == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
