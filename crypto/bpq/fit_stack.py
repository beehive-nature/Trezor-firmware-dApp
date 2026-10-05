"""Worst-case C stack of the bpq entry points on the T3W1 target.

    python3 crypto/bpq/fit_stack.py <dir of .ci files> [--vla FN=BYTES]...
        [--indirect CALLER=TARGET]... <root function>...

Reads GCC's -fcallgraph-info=su output (one .ci file per translation unit,
compiled with the hardware build's own flags) and prints, for each root, the
deepest path through the static call graph and the sum of its frames.

It refuses to print a number it cannot stand behind: a recursive cycle, an
indirect call, or a frame GCC marks dynamic on a reachable function is
reported and the root is marked INCOMPLETE, unless the caller names a bound:
--vla FN=BYTES adds BYTES (the largest variable-length array FN can allocate,
argued from its source) to FN's static frame; --indirect CALLER=TARGET says the
function pointer CALLER calls is TARGET. Each bound used is printed with the
result. Calls to functions with no frame information (libc memcpy/memset,
compiler helpers) are listed by name; their frames are not counted.
"""

import re
import sys
from pathlib import Path

NODE = re.compile(r'node:\s*\{\s*title:\s*"([^"]+)"\s*label:\s*"([^"]*)"')
EDGE = re.compile(r'edge:\s*\{\s*sourcename:\s*"([^"]+)"\s*targetname:\s*"([^"]+)"')
FRAME = re.compile(r"\\n(\d+) bytes \((static|dynamic|dynamic,bounded)\)")


def load(ci_dir: Path):
    frames: dict[str, tuple[int, str, str]] = {}  # name -> (bytes, kind, unit)
    local: dict[tuple[str, str], tuple[int, str]] = {}  # (unit, name) -> frame
    edges: list[tuple[str, str, str]] = []  # (unit, src, dst)
    for ci in sorted(ci_dir.glob("*.ci")):
        unit = ci.name
        text = ci.read_text(errors="replace")
        for title, label in NODE.findall(text):
            m = FRAME.search(label)
            if m:
                frame = (int(m.group(1)), m.group(2))
                local[(unit, title)] = frame
                frames.setdefault(title, (frame[0], frame[1], unit))
        for src, dst in EDGE.findall(text):
            edges.append((unit, src, dst))
    graph: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for unit, src, dst in edges:
        # resolve within the translation unit first (static functions), then
        # to the global definition
        if (unit, dst) in local:
            target = (unit, dst)
        elif dst in frames:
            target = (frames[dst][2], dst)
        else:
            target = ("?", dst)
        graph.setdefault((unit, src), []).append(target)
    return local, graph


def bare(title: str) -> str:
    """GCC titles a static function "<file>:<name>"."""
    return title.rsplit(":", 1)[-1]


def worst(root, local, graph, vla, indirect):
    problems: set[str] = set()
    unknown: set[str] = set()
    used: set[str] = set()
    memo: dict = {}
    by_bare: dict[str, tuple[str, str]] = {}
    for k in local:
        by_bare.setdefault(bare(k[1]), k)

    def walk(node, stack):
        if node in memo:
            return memo[node]
        if node in stack:
            problems.add(f"recursion through {node[1]}")
            return 0, [node[1]]
        unit, name = node
        if unit == "?":
            if "indirect" not in name:
                unknown.add(name)
            return 0, []
        size, kind = local[node]
        short = bare(name)
        if kind != "static":
            if short in vla:
                size += vla[short]
                used.add(f"--vla {short}={vla[short]}")
            else:
                problems.add(f"{kind} frame in {short}")
        children = list(graph.get(node, []))
        if any(c[0] == "?" and "indirect" in c[1] for c in children):
            if short in indirect and indirect[short] in by_bare:
                children.append(by_bare[indirect[short]])
                used.add(f"--indirect {short}={indirect[short]}")
            else:
                problems.add(f"indirect call in {short}")
        best = (0, [])
        for child in children:
            got = walk(child, stack | {node})
            if got[0] > best[0]:
                best = got
        result = (size + best[0], [f"{short} {size}"] + best[1])
        memo[node] = result
        return result

    starts = [k for k in local if bare(k[1]) == root]
    if not starts:
        return None
    total, path = max((walk(s, frozenset()) for s in starts), key=lambda r: r[0])
    return total, path, problems, unknown, used


def main():
    ci_dir = Path(sys.argv[1])
    vla: dict[str, int] = {}
    indirect: dict[str, str] = {}
    roots = []
    args = sys.argv[2:]
    while args:
        a = args.pop(0)
        if a == "--vla":
            fn, n = args.pop(0).split("=")
            vla[fn] = int(n)
        elif a == "--indirect":
            src, dst = args.pop(0).split("=")
            indirect[src] = dst
        else:
            roots.append(a)
    local, graph = load(ci_dir)
    rc = 0
    for root in roots:
        got = worst(root, local, graph, vla, indirect)
        if got is None:
            print(f"{root}: NOT FOUND in {ci_dir}")
            rc = 1
            continue
        total, path, problems, unknown, used = got
        state = "INCOMPLETE: " + "; ".join(sorted(problems)) if problems else "complete"
        print(f"{root}: {total} B worst-case stack ({state})")
        print("  path: " + " > ".join(path))
        if used:
            print("  bounds used: " + ", ".join(sorted(used)))
        if unknown:
            print("  not counted (no frame info): " + ", ".join(sorted(unknown)))
        if problems:
            rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
