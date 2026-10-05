#!/usr/bin/env python3
"""
Smite Scenario Comparison

Runs fuzzing trials of several scenarios built from one smite checkout, by default
the byte-level baseline (`encrypted_bytes`) against the IR scenario (`ir`), and lays
them out for `smite-evaluation.py`.

Trials, Docker builds and the dashboard come from `smite-orchestrator.py`, so a trial
here is the exact afl-fuzz invocation the orchestrator runs. The difference is what
an arm is: the orchestrator compares checkouts running one scenario, this script
compares scenarios of one checkout. Each scenario is also its output label. The queue
interleaves the arms trial by trial, so they run side by side under the same load,
and each target can get its own number of trials.

Requirements: same as smite-orchestrator.py.

Generated Directory Structure:
    <out_dir>/
    ├── .default-seeds/                  # Fallback '\x00' seed (if --seed-dir omitted)
    ├── encrypted_bytes/                 # Baseline arm
    │   └── <target>/trial-NN/afl-out/default/
    └── ir/                              # Experimental arm
        └── <target>/trial-NN/afl-out/default/

Usage:
    python smite-scenario-compare.py \
    --out-dir OUT_DIR \
    --targets TARGET[,TARGET...] \
    --cores CORE[,CORE...] \
    --afl-dir AFL_DIR \
    [--scenarios BASELINE,EXPERIMENTAL] \
    [--smite-dir SMITE_DIR] \
    [--trials N] \
    [--target-trials TARGET=N[,TARGET=N...] | --trial-ids ID[,ID...]] \
    [--timeout SECONDS] \
    [--exec-timeout MS] \
    [--hang-timeout MS] \
    [--seed-dir SEED_DIR]

Examples:
    # 30 trials of 24 hours per arm and target, 12 cores per arm
    python smite-scenario-compare.py \
        --out-dir ./compare \
        --targets cln,lnd,ldk,eclair \
        --cores 0-23 \
        --afl-dir ~/AFLplusplus

    # 30 trials on every target except Eclair (10) and LND (20)
    python smite-scenario-compare.py \
        --out-dir ./compare \
        --targets cln,lnd,ldk,eclair \
        --cores 0-23 \
        --trials 30 \
        --target-trials eclair=10,lnd=20 \
        --afl-dir ~/AFLplusplus

    # Re-run IR trials 3 and 7 of LND, keeping every other trial
    python smite-scenario-compare.py \
        --out-dir ./compare \
        --scenarios ir \
        --targets lnd \
        --cores 0,1 \
        --trial-ids 3,7 \
        --afl-dir ~/AFLplusplus

    # Evaluate
    python smite-evaluation.py ./compare encrypted_bytes ir
"""

import argparse
import importlib.util
import math
import os
import signal
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def _load_orchestrator():
    """Import smite-orchestrator.py, whose hyphenated name rules out a plain import."""
    path = Path(__file__).with_name("smite-orchestrator.py")
    spec = importlib.util.spec_from_file_location("smite_orchestrator", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


orch = _load_orchestrator()


# ────────────────────────────  ARGUMENTS  ────────────────────────────


def split_list(spec: str) -> list[str]:
    return [item.strip() for item in spec.split(",") if item.strip()]


def parse_cores(spec: str) -> list[int]:
    """Parse '0,1,2' or '0-11,16' into a list of distinct cores."""
    cores = []
    try:
        for part in split_list(spec):
            lo, _, hi = part.partition("-")
            cores.extend(range(int(lo), int(hi or lo) + 1))
    except ValueError:
        sys.exit(f"ERROR: --cores must list cores or ranges, e.g. '0-11,16'. Got '{spec}'.")
    if not cores or len(set(cores)) != len(cores):
        sys.exit(f"ERROR: --cores must name each core once. Got '{spec}'.")
    return cores


def parse_trial_plan(args, targets: list[str]) -> dict[str, list[int]]:
    """Trial numbers to run for each target, the same for every arm."""
    if args.trial_ids:
        if args.target_trials:
            sys.exit("ERROR: --trial-ids and --target-trials are mutually exclusive.")
        try:
            ids = [int(x) for x in split_list(args.trial_ids)]
        except ValueError:
            sys.exit("ERROR: --trial-ids must be a comma-separated list of integers.")
        return {t: ids for t in targets}

    counts = {t: args.trials for t in targets}
    for item in split_list(args.target_trials or ""):
        target, _, n = item.partition("=")
        target = target.strip()
        if target not in counts:
            sys.exit(f"ERROR: --target-trials names '{target}', which is not in --targets.")
        try:
            counts[target] = int(n)
        except ValueError:
            sys.exit(f"ERROR: --target-trials entry '{item}' must be TARGET=N.")

    for target, n in counts.items():
        if n < 1:
            sys.exit(f"ERROR: '{target}' needs at least one trial, got {n}.")
    return {t: list(range(1, n + 1)) for t, n in counts.items()}


def parse_args():
    """Parse CLI args and resolve all filesystem paths to absolute up front."""
    p = argparse.ArgumentParser(
        description="Compare smite scenarios on the same targets and checkout"
    )
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--targets", required=True, help="e.g. cln,lnd,ldk,eclair")
    p.add_argument("--cores", required=True, help="e.g. 0,1,2,3 or 0-23")
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument(
        "--scenarios",
        default="encrypted_bytes,ir",
        help="Arms to run, baseline first. Each scenario is also its output label.",
    )
    p.add_argument(
        "--smite-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Smite checkout every arm is built from (default: this script's repo).",
    )
    p.add_argument("--trials", type=int, default=30, help="Trials per arm and target")
    p.add_argument(
        "--target-trials",
        help="Per-target override of --trials, e.g. 'eclair=10,lnd=20'.",
    )
    p.add_argument(
        "--trial-ids",
        help="Trial numbers to run on every target and arm, e.g. '1,5,15'. Overrides --trials.",
    )
    p.add_argument("--timeout", type=int, default=86400)
    p.add_argument(
        "--exec-timeout", type=int, default=2000, help="AFL++ exec timeout in ms (-t)"
    )
    p.add_argument(
        "--hang-timeout",
        type=int,
        default=4000,
        help="AFL++ hang timeout in ms (AFL_HANG_TMOUT)",
    )
    p.add_argument("--seed-dir", type=Path)

    args = p.parse_args()

    args.out_dir = args.out_dir.resolve()
    args.afl_dir = args.afl_dir.resolve()
    args.smite_dir = args.smite_dir.expanduser().resolve()
    if args.seed_dir:
        args.seed_dir = args.seed_dir.resolve()

    return args


# ────────────────────────────  CAMPAIGN  ────────────────────────────


def print_campaign_summary(
    console: Console,
    scenarios: list[str],
    plan: dict[str, list[int]],
    cores: list[int],
    total: int,
    timeout: int,
):
    """Display the arms, trials per target and a wall-clock estimate."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", justify="right")
    grid.add_column(style="white")

    grid.add_row("Arms", ", ".join(scenarios))
    for target, ids in plan.items():
        grid.add_row(f"Trials per arm ({target})", str(len(ids)))
    grid.add_row("Allocated cores", str(len(cores)))
    grid.add_row("Total trials", str(total))

    # Upper bound: every round waits for its slowest trial.
    rounds = math.ceil(total / len(cores))
    grid.add_row("Estimated wall-clock", f"{rounds * timeout / 3600:.1f} hours")

    console.print(Panel(grid, title="Comparison Configuration", border_style="green"))
    console.print()


def worker_thread(core: int, work: Queue, args, state):
    """Per-core worker loop: run trials off the shared queue until it is empty or
    shutdown is requested."""
    while not state.shutdown.is_set():
        try:
            scenario, target, trial_num = work.get_nowait()
        except Empty:
            state.update_worker(
                core,
                task="Idle",
                status="-",
                color="dim",
                is_active=False,
                execs_sec=0.0,
                edges=0,
            )
            return

        config = orch.TrialConfig(
            core=core,
            label=scenario,
            target=target,
            trial_num=trial_num,
            scenario=scenario,
            out_dir=args.out_dir,
            smite_dir=args.smite_dir,
            afl_dir=args.afl_dir,
            timeout=args.timeout,
            exec_timeout=args.exec_timeout,
            hang_timeout=args.hang_timeout,
            seed_dir=args.seed_dir,
        )
        orch.TrialRunner(config, state).run()
        work.task_done()


def main():
    args = parse_args()
    console = Console()

    scenarios = split_list(args.scenarios)
    if not scenarios or len(set(scenarios)) != len(scenarios):
        sys.exit("ERROR: --scenarios must name each scenario once.")
    targets = split_list(args.targets)
    cores = parse_cores(args.cores)
    plan = parse_trial_plan(args, targets)

    if len(cores) % len(scenarios):
        console.print(
            f"[yellow]Warning: {len(cores)} cores do not split evenly across "
            f"{len(scenarios)} arms, so some trial pairs will not run side by side.[/]"
        )

    orch.ensure_seed_dir(args, console)

    smite = {"smite": args.smite_dir}
    orch.save_commit_metadata(
        args.out_dir, {s: args.smite_dir for s in scenarios}, console
    )
    orch.EnvironmentManager.validate(args.afl_dir, smite, console)
    orch.EnvironmentManager.validate_paths(args.afl_dir, smite, console)

    for scenario in scenarios:
        orch.EnvironmentManager.build_docker_images(
            targets, scenario, {scenario: args.smite_dir}, console
        )
    if any(s.startswith("ir") for s in scenarios):
        orch.EnvironmentManager.build_ir_mutator(smite, console)

    state = orch.CampaignState(scenarios, cores)

    def _handle_sigint(sig, frame):
        """First Ctrl+C: stop queueing new trials and kill active fuzzers.
        Second Ctrl+C: force-quit immediately."""
        if state.shutdown.is_set():
            console.print("\n[bold red]Force-quitting immediately![/]")
            os._exit(1)
        state.shutdown.set()
        console.print(
            "\n[bold yellow]Interrupt received, killing fuzzers... (Ctrl+C again to force quit)[/]"
        )
        with state.pid_lock:
            for pid in state.active_pids:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass

    signal.signal(signal.SIGINT, _handle_sigint)

    # Arms alternate trial by trial so both always hold about half the cores.
    work = Queue()
    for target, ids in plan.items():
        for i in ids:
            for scenario in scenarios:
                work.put((scenario, target, i))
                state.summary[scenario]["total"] += 1
    state.total = sum(s["total"] for s in state.summary.values())

    print_campaign_summary(console, scenarios, plan, cores, state.total, args.timeout)

    threads = [
        threading.Thread(
            target=worker_thread, args=(c, work, args, state), daemon=True
        )
        for c in cores
    ]

    with Live(
        orch.DashboardRenderer.render(state), refresh_per_second=4, console=console
    ) as live:
        for t in threads:
            t.start()
        while any(t.is_alive() for t in threads):
            live.update(orch.DashboardRenderer.render(state))
            time.sleep(0.25)
        for t in threads:
            t.join()

        live.update(orch.DashboardRenderer.render(state))

    if state.shutdown.is_set():
        console.print("[bold yellow]Stopped early due to interrupt.[/]")
    else:
        console.print("\n[bold green]=== All trials complete! Ready for analysis. ===[/]")
        if len(scenarios) == 2:
            console.print(
                f"Run: [cyan]python scripts/smite-evaluation.py {args.out_dir} "
                f"{scenarios[0]} {scenarios[1]}[/]"
            )


if __name__ == "__main__":
    main()
