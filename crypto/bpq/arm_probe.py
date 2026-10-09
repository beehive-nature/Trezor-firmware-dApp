#!/usr/bin/env python3
"""Compile one bpq C unit for the T3W1 hardware target with the exact arguments a
previous hardware build used, read from that build's compile database.

This is the reproducer behind crypto/bpq/ARM_COMPILE_RECEIPT.md. It does not
build firmware; it compiles a single translation unit the way the firmware
build would, so the one ARM-only diagnostic in the vendored SPHINCS+ reference
can be shown and shown fixed without a device and without lifting the
emulator-only gate.

Usage:
  arm_probe.py <unit, e.g. bpq_slh.c> <out.o> [--db <firmware.cc.json>]
               [--cc <arm-none-eabi-gcc>] [--src-root <checkout>] [-- extra gcc flags]

Defaults: the compile database of a T3W1 hardware build that had bpq gated in
(a build with the gate lifted writes it at
core/build-xtask/artifacts/T3W1/firmware.cc.json), the Arm GNU Toolchain
13.3.Rel1 from the fork's nix shell, and this checkout as the source root.
The compiler runs without a shell. Prints rc, the compiler's stderr verbatim,
and on success the exported symbols that are not prefixed `bpq`.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_DB = os.path.join(DEFAULT_ROOT, "core", "build-xtask", "artifacts", "T3W1", "firmware.cc.json")
DEFAULT_CC = "arm-none-eabi-gcc"


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    unit, out = argv[1], argv[2]
    rest = argv[3:]
    db, cc, root = DEFAULT_DB, DEFAULT_CC, DEFAULT_ROOT
    extra = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--db":
            db = rest[i + 1]; i += 2
        elif a == "--cc":
            cc = rest[i + 1]; i += 2
        elif a == "--src-root":
            root = os.path.abspath(rest[i + 1]); i += 2
        elif a == "--":
            extra = rest[i + 1:]; break
        else:
            sys.exit("refuse: unknown argument %r" % a)
    entries = json.load(open(db))
    hits = [e for e in entries if e.get("file", "").endswith("/trezor-crypto/bpq/" + unit)]
    if len(hits) != 1:
        sys.exit("refuse: %d database entries for %s" % (len(hits), unit))
    e = hits[0]
    db_root = e["file"].split("/core/vendor/trezor-crypto/")[0] + "/"
    src = e["file"].replace(db_root, root + "/", 1)
    cwd = e["directory"].replace(db_root, root + "/", 1)
    args = list(e["arguments"])
    args[0] = cc
    new = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o":
            new += ["-o", out]; i += 2; continue
        if a == e["file"]:
            new.append(src); i += 1; continue
        new.append(a); i += 1
    if extra:
        k = new.index("-c")
        new = new[:k] + extra + new[k:]
    print("cwd:", cwd)
    print("src:", src)
    print("cc:", new[0], "| args:", len(new), "| extra:", extra)
    p = subprocess.run(new, cwd=cwd, capture_output=True, text=True)
    print("rc=%d" % p.returncode)
    sys.stdout.write(p.stderr)
    if p.returncode == 0:
        nm = os.path.join(os.path.dirname(cc), "arm-none-eabi-nm") if os.sep in cc else "arm-none-eabi-nm"
        syms = subprocess.run([nm, out], capture_output=True, text=True).stdout
        exported = [l for l in syms.splitlines() if " T " in l]
        stray = [l for l in exported if not l.split()[-1].startswith("bpq")]
        print("exported T symbols: %d; not prefixed bpq: %s" % (len(exported), stray or "none"))
        for l in exported:
            if "merkle" in l or "public_from_seed" in l:
                print(l)
    return p.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
