#!/usr/bin/env python3
"""
Smite Protocol Depth Measure

Measures how far into channel establishment each arm of a comparison got. For each
stage of the single-funded flow (open_channel, funding_created, channel_ready) it
reports whether the target handled the message, meaning its handler for that message
ran, and whether it accepted it, meaning it replied or recorded the message and moved
on. Some targets run a handler in any state and reject a message for an unknown
channel there, so only acceptance shows that the stage's state was reached.

For each arm and target, the queues of all trials are merged, reduced with
`afl-cmin -X` against the Nyx image the trials ran, and replayed with
`coverage-report.sh` on a coverage build of the target. The coverage build is pinned
to the versions of the production Dockerfile. Each stage is a marker line in the
target's source, located by regex inside the coverage image, so line numbers always
match the code that ran.

Requirements: Docker, an AFL++ checkout with Nyx mode, the trial images and the
output layout of smite-scenario-compare.py (each arm's label is its scenario).

Usage:
    python smite-depth.py EVAL_DIR --afl-dir AFL_DIR \
        [--labels encrypted_bytes,ir] [--targets cln,lnd,ldk,eclair] \
        [--cores 0-7] [--jobs 16] [--out-dir DIR] [--force]

Output (<out_dir>, default <EVAL_DIR>/depth):
    depth.csv, depth.md          One row per target, arm, stage and level
    <label>/<target>/cmin/       Reduced corpus that was replayed
    <label>/<target>/coverage/   Merged coverage data and HTML report
"""

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

SMITE_DIR = Path(__file__).resolve().parent.parent
STAGES = ("open_channel", "funding_created", "channel_ready")
LEVELS = ("handled", "accepted")
EXEC_TIMEOUT_MS = 5000
# JaCoCo records the instructions covered on a line, not how often it ran.
HAS_EXEC_COUNTS = {"cln": True, "lnd": True, "ldk": True, "eclair": False}


@dataclass(frozen=True)
class Marker:
    """A source line whose execution shows a stage was reached.

    `after` picks the occurrence: the marker is the first line matching `line` at or
    after the first line matching `after`.
    """

    file: str
    line: str
    after: str = ""


M = Marker
# A stage counts as reached if any of its markers ran. Markers are fixed against the
# versions pinned in workloads/*/Dockerfile and checked again at run time.
MARKERS = {
    "cln": {
        ("open_channel", "handled"): [M("openingd/openingd.c", r"if \(!fromwire_open_channel\(")],
        ("open_channel", "accepted"): [
            M("openingd/openingd.c", r"peer_write\(state->pps, take\(msg\)\);", after=r"towire_accept_channel\(")
        ],
        ("funding_created", "handled"): [M("openingd/openingd.c", r"if \(!fromwire_funding_created\(")],
        ("funding_created", "accepted"): [M("openingd/openingd.c", r"towire_funding_signed\(")],
        ("channel_ready", "handled"): [
            M("channeld/channeld.c", r"if \(peer->channel_ready\[REMOTE\]\)", after=r"^static void handle_peer_channel_ready\(")
        ],
        ("channel_ready", "accepted"): [
            M("channeld/channeld.c", r"peer->channel_ready\[REMOTE\] = true;", after=r"^static void handle_peer_channel_ready\(")
        ],
    },
    "lnd": {
        ("open_channel", "handled"): [
            M("funding/manager.go", r"msg \*lnwire\.OpenChannel\) \{", after=r"^func \(f \*Manager\) fundeeProcessOpenChannel\(")
        ],
        ("open_channel", "accepted"): [M("funding/manager.go", r"peer\.SendMessage\(true, &fundingAccept\)")],
        ("funding_created", "handled"): [
            M("funding/manager.go", r"msg \*lnwire\.FundingCreated\) \{", after=r"^func \(f \*Manager\) fundeeProcessFundingCreated\(")
        ],
        ("funding_created", "accepted"): [M("funding/manager.go", r"peer\.SendMessage\(true, fundingSigned\)")],
        ("channel_ready", "handled"): [
            M("funding/manager.go", r"msg \*lnwire\.ChannelReady\) \{", after=r"^func \(f \*Manager\) handleChannelReady\(")
        ],
        ("channel_ready", "accepted"): [
            M("funding/manager.go", r"err = channel\.InsertNextRevocation\(msg\.NextPerCommitmentPoint\)",
              after=r"^func \(f \*Manager\) processChannelReady\(")
        ],
    },
    "ldk": {
        ("open_channel", "handled"): [M("src/ln/channelmanager.rs", r"fn internal_open_channel\(")],
        # ldk-node may accept inbound channels by hand or automatically; either path counts.
        ("open_channel", "accepted"): [
            M("src/ln/channelmanager.rs", r"MessageSendEvent::SendAcceptChannel \{", after=r"fn do_accept_inbound_channel\("),
            M("src/ln/channelmanager.rs", r"MessageSendEvent::SendAcceptChannel \{", after=r"fn internal_open_channel\("),
        ],
        ("funding_created", "handled"): [M("src/ln/channelmanager.rs", r"fn internal_funding_created\(")],
        ("funding_created", "accepted"): [
            M("src/ln/channelmanager.rs", r"MessageSendEvent::SendFundingSigned \{", after=r"fn internal_funding_created\(")
        ],
        ("channel_ready", "handled"): [M("src/ln/channelmanager.rs", r"fn internal_channel_ready\(")],
        ("channel_ready", "accepted"): [
            M("src/ln/channelmanager.rs", r"emit_initial_channel_ready_event!\(pending_events, chan\);",
              after=r"fn internal_channel_ready\(")
        ],
    },
    "eclair": {
        ("open_channel", "handled"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"Helpers\.validateParamsSingleFundedFundee\(",
              after=r"case Event\(open: OpenChannel, d: DATA_WAIT_FOR_OPEN_CHANNEL\)")
        ],
        ("open_channel", "accepted"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"goto\(WAIT_FOR_FUNDING_CREATED\) using DATA_WAIT_FOR_FUNDING_CREATED\(")
        ],
        ("funding_created", "handled"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"val temporaryChannelId = d\.channelParams\.channelId",
              after=r"case Event\(fc@FundingCreated\(")
        ],
        ("funding_created", "accepted"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"val fundingSigned = FundingSigned\(channelId, localSig\)")
        ],
        # Eclair defers a channel_ready that arrives before its own funding confirmation.
        ("channel_ready", "handled"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"val switchToZeroConf = ",
              after=r"case Event\(remoteChannelReady: ChannelReady, d: DATA_WAIT_FOR_FUNDING_CONFIRMED\)"),
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"val d1 = receiveChannelReady\(",
              after=r"case Event\(channelReady: ChannelReady, d: DATA_WAIT_FOR_CHANNEL_READY\)"),
        ],
        ("channel_ready", "accepted"): [
            M("channel/fsm/ChannelOpenSingleFunded.scala", r"goto\(NORMAL\) using d1 storing\(\) sending annSigs_opt\.toSeq",
              after=r"case Event\(channelReady: ChannelReady, d: DATA_WAIT_FOR_CHANNEL_READY\)")
        ],
    },
}

# Where each coverage image keeps the sources its coverage data refers to.
SOURCE_ROOTS = {
    "cln": "/cln",
    "lnd": "/lnd",
    "ldk": "/cargo/registry/src",
    "eclair": "/eclair-src/eclair-core/src/main/scala",
}

print_lock = threading.Lock()


def log(msg: str):
    with print_lock:
        print(msg, flush=True)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, failing loudly with its output on error."""
    res = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if res.returncode != 0:
        raise RuntimeError(
            f"command failed ({res.returncode}): {' '.join(cmd)}\n{(res.stderr or res.stdout)[-2000:]}"
        )
    return res


# ────────────────────────────  CORPUS REDUCTION  ────────────────────────────


def stage_queues(eval_dir: Path, label: str, target: str, stage_dir: Path) -> int:
    """Copy every trial's queue into stage_dir under short names, dropping duplicates.

    Short names keep afl-cmin under NAME_MAX, as smitebot's corpus minimize does.
    """
    queues = sorted(eval_dir.glob(f"{label}/{target}/trial-*/afl-out/default/queue"))
    if not queues:
        raise RuntimeError(f"no queues under {eval_dir}/{label}/{target}")
    stage_dir.mkdir(parents=True)
    seen = set()
    for q in queues:
        for f in sorted(q.iterdir()):
            if not f.is_file():
                continue
            data = f.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest not in seen:
                seen.add(digest)
                (stage_dir / f"{len(seen):06d}").write_bytes(data)
    return len(seen)


def reduce_corpus(args, label: str, target: str, core: int, setup_lock: threading.Lock):
    """Merge the arm's queues and reduce them with afl-cmin under the trials' Nyx image."""
    work = args.out_dir / label / target
    cmin_dir = work / "cmin"
    if cmin_dir.is_dir() and any(cmin_dir.iterdir()) and not args.force:
        log(f"[{label}/{target}] reduced corpus exists, skipping afl-cmin")
        return
    for d in ("stage", "cmin", "sharedir"):
        shutil.rmtree(work / d, ignore_errors=True)

    staged = stage_queues(args.eval_dir, label, target, work / "stage")
    log(f"[{label}/{target}] staged {staged} unique queue entries")

    image = args.nyx_image.format(label=label, target=target, scenario=label)
    with setup_lock:
        run([str(SMITE_DIR / "scripts" / "setup-nyx.sh"), str(work / "sharedir"), image, str(args.afl_dir)])

    env = os.environ.copy()
    env.update({
        "AFL_PATH": str(args.afl_dir),
        "PATH": f"{args.afl_dir}:{env['PATH']}",
        "AFL_NO_AFFINITY": "1",
        "AFL_FORKSRV_INIT_TMOUT": "1800000",
    })
    log(f"[{label}/{target}] afl-cmin on core {core}")
    run(["taskset", "-c", str(core), str(args.afl_dir / "afl-cmin"),
         "-i", str(work / "stage"), "-o", str(cmin_dir), "-t", str(EXEC_TIMEOUT_MS),
         "-X", str(work / "sharedir")], env=env)
    kept = sum(1 for f in cmin_dir.iterdir() if f.is_file())
    log(f"[{label}/{target}] afl-cmin kept {kept} of {staged}")
    shutil.rmtree(work / "sharedir", ignore_errors=True)
    shutil.rmtree(work / "stage", ignore_errors=True)


# ────────────────────────────  COVERAGE REPLAY  ────────────────────────────


def coverage_image(target: str, scenario: str) -> str:
    return f"smite-{target}-{scenario}-coverage"


def pinned_build_args(target: str) -> list[str]:
    """Build args that pin the coverage build to the production Dockerfile's versions."""
    def args_of(path: Path) -> dict:
        return dict(re.findall(r"^ARG (\w+)=(\S+)", path.read_text(), re.M))

    prod = args_of(SMITE_DIR / "workloads" / target / "Dockerfile")
    cov = args_of(SMITE_DIR / "workloads" / target / "Dockerfile.coverage")
    out = []
    for name in sorted(cov.keys() & prod.keys()):
        out += ["--build-arg", f"{name}={prod[name]}"]
    return out


def ensure_coverage_image(target: str, scenario: str, force: bool):
    image = coverage_image(target, scenario)
    exists = subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
    if exists and not force:
        return
    log(f"[{scenario}/{target}] building {image}")
    run(["docker", "build", "-t", image, *pinned_build_args(target), "--build-arg", f"SCENARIO={scenario}",
         "-f", str(SMITE_DIR / "workloads" / target / "Dockerfile.coverage"), str(SMITE_DIR)])


def merged_coverage_path(target: str, cov_dir: Path) -> Path:
    return cov_dir / {"lnd": "coverage.txt", "cln": "merged.profdata", "ldk": "merged.profdata",
                      "eclair": "merged.exec"}[target]


def replay(args, label: str, target: str):
    """Replay the reduced corpus on the coverage build and merge its coverage."""
    work = args.out_dir / label / target
    cov_dir = work / "coverage"
    if merged_coverage_path(target, cov_dir).exists() and not args.force:
        log(f"[{label}/{target}] coverage exists, skipping replay")
        return
    log(f"[{label}/{target}] replaying {sum(1 for _ in (work / 'cmin').iterdir())} inputs")
    env = os.environ.copy()
    env["PARALLEL"] = str(args.jobs)
    run([str(SMITE_DIR / "scripts" / "coverage-report.sh"), target, label, str(work / "cmin"), str(cov_dir)], env=env)


# ────────────────────────────  STAGE MARKERS  ────────────────────────────


def docker_sh(image: str, script: str, cov_dir: Path | None = None) -> str:
    cmd = ["docker", "run", "--rm"]
    if cov_dir is not None:
        # Run as the caller so files written to the mount stay theirs.
        cmd += ["--user", f"{os.getuid()}:{os.getgid()}", "-v", f"{cov_dir}:/output"]
    return run(cmd + [image, "sh", "-c", script]).stdout


def find_source(image: str, target: str, suffix: str) -> str:
    """Absolute path, inside the image, of the one source file ending in suffix."""
    out = docker_sh(image, f"find {SOURCE_ROOTS[target]} -path '*/{suffix}' -type f")
    paths = [p for p in out.split() if p]
    if len(paths) != 1:
        raise RuntimeError(f"{image}: expected one source matching {suffix}, found {paths}")
    return paths[0]


def resolve(marker: Marker, lines: list[str]) -> int:
    """1-based line number of the marker in the source."""
    start = 0
    if marker.after:
        start = next((i for i, l in enumerate(lines) if re.search(marker.after, l)), None)
        if start is None:
            raise RuntimeError(f"anchor {marker.after!r} not found in {marker.file}")
    for i in range(start, len(lines)):
        if re.search(marker.line, lines[i]):
            return i + 1
    raise RuntimeError(f"marker {marker.line!r} not found in {marker.file}")


def line_counts_llvm(target: str, image: str, cov_dir: Path, sources: list[str]) -> dict:
    """{path: {line: count}} from the merged LLVM profile, for the given sources only."""
    objects = ('BIN=/usr/local/bin/lightningd; OBJ=""; '
               'for b in /usr/local/libexec/c-lightning/lightning_* /usr/local/libexec/c-lightning/plugins/*; '
               'do [ -f "$b" ] && OBJ="$OBJ -object=$b"; done'
               if target == "cln" else 'BIN=/usr/local/bin/ldk-node-wrapper; OBJ=""')
    lcov = docker_sh(image, f"{objects}; llvm-cov export -format=lcov $BIN $OBJ "
                            f"-instr-profile=/output/merged.profdata {' '.join(sources)}", cov_dir)
    counts, current = {}, None
    for l in lcov.splitlines():
        if l.startswith("SF:"):
            current = counts.setdefault(l[3:], {})
        elif l.startswith("DA:") and current is not None:
            n, c = l[3:].split(",")[:2]
            current[int(n)] = max(current.get(int(n), 0), int(c))
    return counts


def line_counts_go(cov_dir: Path) -> dict:
    """{import path: {line: count}} from Go's text coverage profile."""
    counts = {}
    for l in (cov_dir / "coverage.txt").read_text().splitlines()[1:]:
        m = re.match(r"(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$", l)
        if not m:
            continue
        f, start, end, c = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        lines = counts.setdefault(f, {})
        for n in range(start, end + 1):
            lines[n] = max(lines.get(n, 0), c)
    return counts


def line_counts_jacoco(image: str, cov_dir: Path) -> dict:
    """{package/sourcefile: {line: covered instructions}} from the merged JaCoCo data."""
    docker_sh(image, "java -jar /jacococli.jar report /output/merged.exec "
                     "--classfiles $(ls /opt/eclair/lib/eclair-core*.jar) --xml /output/jacoco.xml", cov_dir)
    counts = {}
    for pkg in ET.parse(cov_dir / "jacoco.xml").getroot().iter("package"):
        for sf in pkg.iter("sourcefile"):
            counts[f"{pkg.get('name')}/{sf.get('name')}"] = {
                int(l.get("nr")): int(l.get("ci")) for l in sf.iter("line")
            }
    return counts


def lookup(counts: dict, path: str, suffix: str) -> dict:
    """Coverage of the file that is `path`, or the one whose name ends with suffix."""
    if path in counts:
        return counts[path]
    hits = [v for k, v in counts.items() if k.endswith("/" + suffix)]
    if len(hits) != 1:
        raise RuntimeError(f"expected one coverage entry for {suffix}, found {len(hits)}")
    return hits[0]


def measure_stages(args, label: str, target: str) -> list[dict]:
    """One row per stage and level: whether its markers ran, and how often."""
    cov_dir = args.out_dir / label / target / "coverage"
    image = coverage_image(target, label)
    markers = MARKERS[target]
    suffixes = sorted({m.file for ms in markers.values() for m in ms})
    paths = {s: find_source(image, target, s) for s in suffixes}
    sources = {s: docker_sh(image, f"cat {paths[s]}").splitlines() for s in suffixes}

    if target in ("cln", "ldk"):
        counts = line_counts_llvm(target, image, cov_dir, list(paths.values()))
    elif target == "lnd":
        counts = line_counts_go(cov_dir)
    else:
        counts = line_counts_jacoco(image, cov_dir)

    rows = []
    for stage in STAGES:
        for level in LEVELS:
            total, where = 0, []
            for m in markers[(stage, level)]:
                n = resolve(m, sources[m.file])
                file_counts = lookup(counts, paths[m.file], m.file)
                if n not in file_counts:
                    raise RuntimeError(f"{target}: marker line {m.file}:{n} has no coverage data")
                total += file_counts[n]
                where.append(f"{m.file}:{n}")
            hits = total if HAS_EXEC_COUNTS[target] else None
            rows.append({"target": target, "arm": label, "stage": stage, "level": level,
                         "reached": total > 0, "hits": hits, "markers": " ".join(where)})
    return rows


# ────────────────────────────  ENTRY POINT  ────────────────────────────


def parse_cores(spec: str) -> list[int]:
    cores = []
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        cores.extend(range(int(lo), int(hi or lo) + 1))
    return cores


def write_report(out_dir: Path, rows: list[dict], corpus: dict):
    with open(out_dir / "depth.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    labels = sorted({r["arm"] for r in rows})
    with open(out_dir / "depth.md", "w") as f:
        f.write("# Protocol depth\n\nHits are executions of the marker line across the replayed corpus; "
                "targets without execution counts show none.\n\n")
        f.write("| Target | Stage | Level | " + " | ".join(labels) + " |\n")
        f.write("|---|---|---|" + "---|" * len(labels) + "\n")
        for target in dict.fromkeys(r["target"] for r in rows):
            for stage in STAGES:
                for level in LEVELS:
                    cells = []
                    for label in labels:
                        r = next(r for r in rows if (r["target"], r["arm"], r["stage"], r["level"])
                                 == (target, label, stage, level))
                        hits = "" if r["hits"] is None else f" ({r['hits']})"
                        cells.append(f"{'yes' if r['reached'] else 'no'}{hits}")
                    f.write(f"| {target} | {stage} | {level} | " + " | ".join(cells) + " |\n")
        f.write("\n| Target | Arm | Queue entries, all trials | Replayed after afl-cmin |\n|---|---|---|---|\n")
        for (label, target), (queued, kept) in sorted(corpus.items()):
            f.write(f"| {target} | {label} | {queued} | {kept} |\n")


def main():
    p = argparse.ArgumentParser(description="Measure how far into channel establishment each arm got")
    p.add_argument("eval_dir", type=Path, help="Output directory of smite-scenario-compare.py")
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--labels", default="encrypted_bytes,ir", help="Arms to measure; each label is its scenario")
    p.add_argument("--targets", default="cln,lnd,ldk,eclair")
    p.add_argument("--cores", default="0-7", help="Cores for the parallel afl-cmin runs")
    p.add_argument("--jobs", type=int, default=16, help="Parallel replays per coverage run")
    p.add_argument("--nyx-image", default="smite-{label}-{target}-{scenario}",
                   help="Docker image the trials ran, as a format string")
    p.add_argument("--out-dir", type=Path)
    p.add_argument("--force", action="store_true", help="Redo steps whose output already exists")
    args = p.parse_args()

    args.eval_dir = args.eval_dir.resolve()
    args.afl_dir = args.afl_dir.expanduser().resolve()
    args.out_dir = (args.out_dir or args.eval_dir / "depth").resolve()
    labels = [l.strip() for l in args.labels.split(",") if l.strip()]
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    unknown = set(targets) - MARKERS.keys()
    if unknown:
        sys.exit(f"ERROR: no stage markers for {sorted(unknown)}")
    combos = [(l, t) for t in targets for l in labels]
    cores = parse_cores(args.cores)

    setup_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=len(cores)) as pool:
        futures = [pool.submit(reduce_corpus, args, l, t, cores[i % len(cores)], setup_lock)
                   for i, (l, t) in enumerate(combos)]
        for fut in futures:
            fut.result()

    for l, t in combos:
        ensure_coverage_image(t, l, args.force)
        replay(args, l, t)

    rows, corpus = [], {}
    for l, t in combos:
        rows += measure_stages(args, l, t)
        kept = sum(1 for f in (args.out_dir / l / t / "cmin").iterdir() if f.is_file())
        queued = len(list(args.eval_dir.glob(f"{l}/{t}/trial-*/afl-out/default/queue/id:*")))
        corpus[(l, t)] = (queued, kept)

    write_report(args.out_dir, rows, corpus)
    log(f"done: {args.out_dir}/depth.md")


if __name__ == "__main__":
    main()
