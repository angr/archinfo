"""Check archinfo register offsets against libVEX's generated libvex_guest_offsets.h.

Runnable as a pytest test (compares against the header shipped with the installed
pyvex) or as a standalone script with an explicit header path:

    python tests/test_vex_offsets.py [--header /path/to/libvex_guest_offsets.h] [-v]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict

import pytest

try:
    import pyvex
except ImportError:
    pyvex = None

import archinfo

_DEFINE_RE = re.compile(r"#define\s+OFFSET_([a-z0-9]+)_(\w+)\s+(0x[0-9a-fA-F]+|\d+)")


def find_default_header():
    """Locate libvex_guest_offsets.h shipped with the installed pyvex."""
    if pyvex is None:
        return None
    pyvex_dir = os.path.dirname(pyvex.__file__)
    candidates = [
        os.path.join(pyvex_dir, "include", "libvex_guest_offsets.h"),
        os.path.join(pyvex_dir, "..", "vex", "pub", "libvex_guest_offsets.h"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return os.path.normpath(path)
    return None


def parse_header(path):
    """Parse the header into {vex_arch: {reg_name_lower: offset}}."""
    table = defaultdict(dict)
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = _DEFINE_RE.match(line.strip())
            if m is not None:
                table[m.group(1)][m.group(2).lower()] = int(m.group(3), 0)
    return dict(table)


def check_arch(arch, table):
    """Compare one Arch instance's register offsets against the header table.

    Returns (matched, mismatches, archinfo_only, header_only) where mismatches is
    a list of (archinfo_name, vex_name, archinfo_offset, header_offset).
    """
    vex_arch = arch.vex_arch[7:].lower()
    href = table.get(vex_arch)
    if href is None:
        return None
    matched = 0
    mismatches = []
    archinfo_only = []
    seen_header_names = set()

    for reg in arch.register_list:
        # same resolution order as Arch.__init__: vex_name, name, then aliases
        names = ([reg.vex_name] if reg.vex_name else []) + [reg.name] + list(reg.alias_names)
        hit = next((n for n in names if n.lower() in href), None)
        if hit is None:
            archinfo_only.append(reg.name)  # synthetic register, no VEX equivalent
        else:
            seen_header_names.add(hit.lower())
            if reg.vex_offset != href[hit.lower()]:
                mismatches.append((reg.name, hit, reg.vex_offset, href[hit.lower()]))
            else:
                matched += 1
        for subname, suboff, _subsz in reg.subregisters:
            if subname.lower() in href:
                seen_header_names.add(subname.lower())
                if reg.vex_offset + suboff != href[subname.lower()]:
                    mismatches.append(
                        (f"{reg.name}.{subname}", subname, reg.vex_offset + suboff, href[subname.lower()])
                    )
                else:
                    matched += 1

    header_only = sorted(set(href) - seen_header_names)
    return matched, mismatches, archinfo_only, header_only


def iter_vex_arches():
    """Unique VEX-backed arches (one instance per Arch class; offsets are endness-independent)."""
    seen = set()
    for arch in archinfo.all_arches:
        if arch.vex_arch is None or not arch.register_list:
            continue
        if arch.name in seen:
            continue
        seen.add(arch.name)
        yield arch


def run_check(header_path, verbose=False, out=sys.stdout):
    table = parse_header(header_path)
    total_mismatches = 0
    for arch in iter_vex_arches():
        result = check_arch(arch, table)
        if result is None:
            print(f"{arch.name}: vex arch {arch.vex_arch} not present in header", file=out)
            continue
        matched, mismatches, archinfo_only, header_only = result
        total_mismatches += len(mismatches)
        print(
            f"{arch.name} ({arch.vex_arch}): {matched} matched, {len(mismatches)} mismatched, "
            f"{len(archinfo_only)} archinfo-only, {len(header_only)} header-only",
            file=out,
        )
        for name, vex_name, got, want in mismatches:
            print(f"    MISMATCH {name} (vex {vex_name}): archinfo {got:#x} != header {want:#x}", file=out)
        if verbose:
            if archinfo_only:
                print(f"    archinfo-only (synthetic): {', '.join(archinfo_only)}", file=out)
            if header_only:
                print(f"    header-only (no archinfo register): {', '.join(header_only)}", file=out)
    return total_mismatches


@pytest.mark.skipif(pyvex is None, reason="pyvex is not installed")
def test_vex_offsets():
    header = find_default_header()
    if header is None:
        pytest.skip("libvex_guest_offsets.h not found in the pyvex installation")
    assert run_check(header) == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", default=None, help="path to libvex_guest_offsets.h")
    parser.add_argument("-v", "--verbose", action="store_true", help="list archinfo-only and header-only registers")
    args = parser.parse_args()
    header = args.header or find_default_header()
    if header is None:
        print("error: cannot locate libvex_guest_offsets.h; pass --header", file=sys.stderr)
        sys.exit(2)
    print(f"header: {header}")
    n = run_check(header, verbose=args.verbose)
    print(f"total mismatches: {n}")
    sys.exit(0 if n == 0 else 1)
