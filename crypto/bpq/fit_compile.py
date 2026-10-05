"""Recompile chosen translation units of a hardware build for stack analysis.

    python3 crypto/bpq/fit_compile.py <build.cc.json> <out dir> <path suffix>...

Takes each matching entry of the xtask compile database verbatim (the
hardware build's own compiler, flags, defines and includes), sends its object
to <out dir>, and adds only -fstack-usage -fcallgraph-info=su. Nothing in the
tree is written.
"""

import json
import shlex
import subprocess
import sys
from pathlib import Path


def main():
    db = json.loads(Path(sys.argv[1]).read_text())
    out = Path(sys.argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    wanted = sys.argv[3:]
    seen = set()
    rc = 0
    for entry in db:
        f = entry["file"]
        match = next((w for w in wanted if f.endswith(w)), None)
        if match is None or f in seen:
            continue
        seen.add(f)
        args = entry.get("arguments") or shlex.split(entry["command"])
        clean = []
        skip = False
        for a in args:
            if skip:
                skip = False
                continue
            if a == "-o":
                skip = True
                continue
            if a.startswith("-o") and len(a) > 2:
                continue
            clean.append(a)
        stem = Path(f).name.replace(".", "_")
        obj = out / f"{stem}.o"
        cmd = clean + ["-fstack-usage", "-fcallgraph-info=su", "-o", str(obj)]
        if "-c" not in cmd:
            cmd.insert(1, "-c")
        run = subprocess.run(cmd, cwd=entry["directory"], capture_output=True, text=True)
        status = "ok" if run.returncode == 0 else f"FAILED rc={run.returncode}"
        print(f"{status}  {f}  ({clean[0]})")
        if run.returncode != 0:
            print(run.stderr[-2000:])
            rc = 1
    for w in wanted:
        if not any(s.endswith(w) for s in seen):
            print(f"MISSING from compile database: {w}")
            rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
