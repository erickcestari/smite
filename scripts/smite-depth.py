#!/usr/bin/env python3
"""
Smite Protocol Depth Measure

Measures how far into channel establishment each arm of a comparison got. For each
stage of the single-funded flow (open_channel, funding_created, channel_ready) it
counts the replayed inputs that made the target handle the message, meaning its
handler for that message ran, and that made it accept the message, meaning it replied
or recorded the message and moved on. Some targets run a handler in any state and
reject a message for an unknown channel there, so only acceptance shows that the
stage's state was reached. Inputs are counted rather than line executions, because
one IR program can send a message several times and a byte input cannot.

For each arm and target, the queues of all trials are merged, reduced with
`afl-cmin -X` against the Nyx image the trials ran, and replayed with
`coverage-report.sh` on a coverage build of the target. The script refuses a
Dockerfile.coverage that pins other versions than the fuzzed build. Each stage is a
marker line in the target's source, located by regex inside the coverage image, so
line numbers always match the code that ran.

Requirements: Docker, an AFL++ checkout with Nyx mode, the trial images and the
output layout of smite-scenario-compare.py (each arm's label is its scenario).

Usage:
    python smite-depth.py EVAL_DIR --afl-dir AFL_DIR \
        [--labels encrypted_bytes,ir] [--targets cln,lnd,ldk,eclair] \
        [--cores 0-7] [--jobs 16] [--out-dir DIR] [--force]

Output (<out_dir>, default <EVAL_DIR>/depth):
    depth.csv, depth.md          One row per target, arm, stage and level
    depth-inputs.csv             One row per replayed input: which stages and levels it reached
    <label>/<target>/cmin/       Reduced corpus that was replayed
    <label>/<target>/coverage/   Per-input and merged coverage data, HTML report
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
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

SMITE_DIR = Path(__file__).resolve().parent.parent
STAGES = ("open_channel", "funding_created", "channel_ready")
LEVELS = ("handled", "accepted")
EXEC_TIMEOUT_MS = 5000


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
# Eclair's per-input reports analyze only the classes of the marker files, which are
# named after them under this package root. Analyzing the whole jar per input is slow.
ECLAIR_CLASS_ROOT = "fr/acinq/eclair/"

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


def check_coverage_pins(target: str):
    """Fail if Dockerfile.coverage pins a version other than the one the trials fuzzed."""
    def args_of(path: Path) -> dict:
        return dict(re.findall(r"^ARG (\w+)=(\S+)", path.read_text(), re.M))

    prod = args_of(SMITE_DIR / "workloads" / target / "Dockerfile")
    cov = args_of(SMITE_DIR / "workloads" / target / "Dockerfile.coverage")
    drift = [f"{n}={cov[n]} (fuzzed {prod[n]})" for n in sorted(cov.keys() & prod.keys()) if cov[n] != prod[n]]
    if drift:
        sys.exit(f"ERROR: workloads/{target}/Dockerfile.coverage drifted: {', '.join(drift)}")


def ensure_coverage_image(target: str, scenario: str, force: bool):
    check_coverage_pins(target)
    image = coverage_image(target, scenario)
    exists = subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
    if exists and not force:
        return
    log(f"[{scenario}/{target}] building {image}")
    run(["docker", "build", "-t", image, "--build-arg", f"SCENARIO={scenario}",
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


class CoverageContainer:
    """A coverage image kept running, so per-input tools skip docker run's start-up."""

    def __init__(self, image: str, cov_dir: Path):
        self.image, self.cov_dir, self.id = image, cov_dir, None

    def __enter__(self):
        # Run as the caller so files written to the mount stay theirs; Go then needs a
        # cache that user can write.
        self.id = run(["docker", "run", "-d", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                       "-v", f"{self.cov_dir}:/output", "--tmpfs", "/tmp:rw,exec,size=1g",
                       "-e", "HOME=/tmp", "-e", "GOCACHE=/tmp/go-cache", "-e", "GOPATH=/tmp/go",
                       "--entrypoint", "sleep", self.image, "infinity"]).stdout.strip()
        return self

    def __exit__(self, *exc):
        subprocess.run(["docker", "rm", "-f", self.id], capture_output=True)

    def sh(self, script: str) -> str:
        return run(["docker", "exec", self.id, "sh", "-c", script]).stdout


def find_source(c: CoverageContainer, target: str, suffix: str) -> str:
    """Absolute path, inside the image, of the one source file ending in suffix."""
    out = c.sh(f"find {SOURCE_ROOTS[target]} -path '*/{suffix}' -type f")
    paths = [p for p in out.split() if p]
    if len(paths) != 1:
        raise RuntimeError(f"{c.image}: expected one source matching {suffix}, found {paths}")
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


def parse_lcov(lcov: str) -> dict:
    """{path: {line: count}} from an lcov export."""
    counts, current = {}, None
    for l in lcov.splitlines():
        if l.startswith("SF:"):
            current = counts.setdefault(l[3:], {})
        elif l.startswith("DA:") and current is not None:
            n, c = l[3:].split(",")[:2]
            current[int(n)] = max(current.get(int(n), 0), int(c))
    return counts


def parse_go_profile(text: str) -> dict:
    """{import path: {line: count}} from Go's text coverage profile."""
    counts = {}
    for l in text.splitlines():
        m = re.match(r"(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$", l)
        if not m:
            continue
        f, start, end, c = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        lines = counts.setdefault(f, {})
        for n in range(start, end + 1):
            lines[n] = max(lines.get(n, 0), c)
    return counts


def parse_jacoco_xml(xml: str) -> dict:
    """{package/sourcefile: {line: covered instructions}} from a JaCoCo XML report."""
    counts = {}
    for pkg in ET.fromstring(xml).iter("package"):
        for sf in pkg.iter("sourcefile"):
            counts[f"{pkg.get('name')}/{sf.get('name')}"] = {
                int(l.get("nr")): int(l.get("ci")) for l in sf.iter("line")
            }
    return counts


def llvm_export(target: str, profdata: str, sources: list[str]) -> str:
    """Shell that prints the lcov of the given sources from one LLVM profile."""
    if target == "cln":
        objects = ('BIN=/usr/local/bin/lightningd; OBJ=""; '
                   'for b in /usr/local/libexec/c-lightning/lightning_* /usr/local/libexec/c-lightning/plugins/*; '
                   'do if [ -f "$b" ]; then OBJ="$OBJ -object=$b"; fi; done; ')
    else:
        objects = 'BIN=/usr/local/bin/ldk-node-wrapper; OBJ=""; '
    return f"{objects}llvm-cov export -format=lcov $BIN $OBJ -instr-profile={profdata} {' '.join(sources)}"


def merged_line_counts(c: CoverageContainer, target: str, paths: dict) -> dict:
    """Line coverage of the whole replayed corpus, from the merged profile."""
    if target in ("cln", "ldk"):
        return parse_lcov(c.sh(llvm_export(target, "/output/merged.profdata", list(paths.values()))))
    if target == "lnd":
        return parse_go_profile((c.cov_dir / "coverage.txt").read_text())
    # The whole jar rather than the extracted classes, so a class the extraction
    # missed makes the per-input and merged results disagree.
    c.sh("java -jar /jacococli.jar report /output/merged.exec "
         "--classfiles $(ls /opt/eclair/lib/eclair-core*.jar) --xml /output/jacoco.xml > /dev/null")
    return parse_jacoco_xml((c.cov_dir / "jacoco.xml").read_text())


def extract_eclair_classes(c: CoverageContainer, suffixes: list[str]):
    """Copy the classes of the marker files out of Eclair's jar into /output/classes."""
    jars = c.sh("ls /opt/eclair/lib/eclair-core*.jar").split()
    if len(jars) != 1:
        raise RuntimeError(f"{c.image}: expected one eclair-core jar, found {jars}")
    jar = c.cov_dir / "eclair-core.jar"
    run(["docker", "cp", f"{c.id}:{jars[0]}", str(jar)])
    prefixes = tuple(ECLAIR_CLASS_ROOT + s.removesuffix(".scala") for s in suffixes)
    shutil.rmtree(c.cov_dir / "classes", ignore_errors=True)
    with zipfile.ZipFile(jar) as z:
        names = [n for n in z.namelist() if n.startswith(prefixes) and n.endswith(".class")]
        if not names:
            raise RuntimeError(f"no classes under {prefixes} in {jars[0]}")
        z.extractall(c.cov_dir / "classes", names)
    jar.unlink()


def input_line_counts(c: CoverageContainer, target: str, paths: dict, input_dir: str) -> dict:
    """Line coverage of one replayed input, from its own profile."""
    tmp = "/tmp/" + Path(input_dir).name
    if target in ("cln", "ldk"):
        return parse_lcov(c.sh(f"set -e; llvm-profdata merge -sparse {input_dir}/*.profraw -o {tmp}.profdata; "
                               f"{llvm_export(target, tmp + '.profdata', list(paths.values()))}; "
                               f"rm -f {tmp}.profdata"))
    if target == "lnd":
        greps = " ".join(f"-e '/{s}:'" for s in paths)
        return parse_go_profile(c.sh(f"set -e; go tool covdata textfmt -i={input_dir} -o={tmp}.txt; "
                                     f"grep -F {greps} {tmp}.txt || [ $? -eq 1 ]; rm -f {tmp}.txt"))
    return parse_jacoco_xml(c.sh(f"set -e; java -jar /jacococli.jar report {input_dir}/jacoco.exec "
                                 f"--classfiles /output/classes --xml {tmp}.xml > /dev/null; "
                                 f"cat {tmp}.xml; rm -f {tmp}.xml"))


def lookup(counts: dict, path: str, suffix: str) -> dict | None:
    """Coverage of the file that is `path`, or the one whose name ends with suffix."""
    if path in counts:
        return counts[path]
    hits = [v for k, v in counts.items() if k.endswith("/" + suffix)]
    if len(hits) > 1:
        raise RuntimeError(f"expected one coverage entry for {suffix}, found {len(hits)}")
    return hits[0] if hits else None


def reached(counts: dict, paths: dict, lines: list[tuple[str, int]]) -> bool:
    """Whether any marker line ran. A file missing from an input's profile did not run."""
    return any((lookup(counts, paths[suffix], suffix) or {}).get(n, 0) > 0 for suffix, n in lines)


def measure_stages(args, label: str, target: str) -> tuple[list[dict], list[dict]]:
    """Per stage and level, how many inputs ran a marker line; and per input, what it reached."""
    cov_dir = args.out_dir / label / target / "coverage"
    markers = MARKERS[target]
    suffixes = sorted({m.file for ms in markers.values() for m in ms})
    keys = [(s, l) for s in STAGES for l in LEVELS]
    inputs = sorted((d for d in (cov_dir / "covdata").iterdir() if d.is_dir() and any(d.iterdir())),
                    key=lambda d: int(d.name.removeprefix("input-")))

    with CoverageContainer(coverage_image(target, label), cov_dir) as c:
        paths = {s: find_source(c, target, s) for s in suffixes}
        sources = {s: c.sh(f"cat {paths[s]}").splitlines() for s in suffixes}
        lines = {k: [(m.file, resolve(m, sources[m.file])) for m in markers[k]] for k in keys}

        merged = merged_line_counts(c, target, paths)
        for k in keys:
            for suffix, n in lines[k]:
                if n not in (lookup(merged, paths[suffix], suffix) or {}):
                    raise RuntimeError(f"{target}: marker line {suffix}:{n} has no coverage data")

        if target == "eclair":
            extract_eclair_classes(c, suffixes)

        def measure_input(d: Path) -> dict:
            counts = input_line_counts(c, target, paths, f"/output/covdata/{d.name}")
            return {f"{s}_{l}": int(reached(counts, paths, lines[(s, l)])) for s, l in keys}

        log(f"[{label}/{target}] measuring {len(inputs)} inputs")
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            flags = list(pool.map(measure_input, inputs))

    input_rows = [{"target": target, "arm": label, "input": d.name, **f} for d, f in zip(inputs, flags)]
    rows = []
    for s, l in keys:
        n_inputs = sum(r[f"{s}_{l}"] for r in input_rows)
        # The merged profile sums the inputs' profiles, so the two must agree on whether a line ran.
        if (n_inputs > 0) != reached(merged, paths, lines[(s, l)]):
            raise RuntimeError(f"{label}/{target}: per-input and merged coverage disagree on {s} {l}")
        rows.append({"target": target, "arm": label, "stage": s, "level": l, "inputs": n_inputs,
                     "markers": " ".join(f"{f}:{n}" for f, n in lines[(s, l)])})
    return rows, input_rows


# ────────────────────────────  ENTRY POINT  ────────────────────────────


def parse_cores(spec: str) -> list[int]:
    cores = []
    for part in spec.split(","):
        lo, _, hi = part.strip().partition("-")
        cores.extend(range(int(lo), int(hi or lo) + 1))
    return cores


def write_csv(path: Path, rows: list[dict]):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def write_report(out_dir: Path, rows: list[dict], input_rows: list[dict], corpus: dict):
    write_csv(out_dir / "depth.csv", rows)
    write_csv(out_dir / "depth-inputs.csv", input_rows)

    labels = sorted({r["arm"] for r in rows})
    with open(out_dir / "depth.md", "w") as f:
        f.write("# Protocol depth\n\nReplayed inputs whose coverage includes a marker line of the stage.\n\n")
        f.write("| Target | Stage | Level | " + " | ".join(labels) + " |\n")
        f.write("|---|---|---|" + "---|" * len(labels) + "\n")
        for target in dict.fromkeys(r["target"] for r in rows):
            for stage in STAGES:
                for level in LEVELS:
                    cells = [str(next(r["inputs"] for r in rows
                                      if (r["target"], r["arm"], r["stage"], r["level"]) == (target, label, stage, level)))
                             for label in labels]
                    f.write(f"| {target} | {stage} | {level} | " + " | ".join(cells) + " |\n")
        f.write("\n| Target | Arm | Queue entries, all trials | Replayed after afl-cmin | With coverage data |\n"
                "|---|---|---|---|---|\n")
        for (label, target), (queued, kept, measured) in sorted(corpus.items()):
            f.write(f"| {target} | {label} | {queued} | {kept} | {measured} |\n")


def main():
    p = argparse.ArgumentParser(description="Measure how far into channel establishment each arm got")
    p.add_argument("eval_dir", type=Path, help="Output directory of smite-scenario-compare.py")
    p.add_argument("--afl-dir", required=True, type=Path)
    p.add_argument("--labels", default="encrypted_bytes,ir", help="Arms to measure; each label is its scenario")
    p.add_argument("--targets", default="cln,lnd,ldk,eclair")
    p.add_argument("--cores", default="0-7", help="Cores for the parallel afl-cmin runs")
    p.add_argument("--jobs", type=int, default=16, help="Parallel jobs for the replays and the per-input measure")
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

    rows, input_rows, corpus = [], [], {}
    for l, t in combos:
        stage_rows, inputs = measure_stages(args, l, t)
        rows += stage_rows
        input_rows += inputs
        kept = sum(1 for f in (args.out_dir / l / t / "cmin").iterdir() if f.is_file())
        queued = len(list(args.eval_dir.glob(f"{l}/{t}/trial-*/afl-out/default/queue/id:*")))
        corpus[(l, t)] = (queued, kept, len(inputs))

    write_report(args.out_dir, rows, input_rows, corpus)
    log(f"done: {args.out_dir}/depth.md")


if __name__ == "__main__":
    main()
