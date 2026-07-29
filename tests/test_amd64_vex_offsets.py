"""Validate that every AMD64 register resolves to a real VEX guest offset.

Arch.__init__ silently assigns registers a synthetic offset (past the end of
any real guest state) when their name is not found in pyvex's guest_offsets
table.  A renamed or missing VEX-side register therefore produces quietly
wrong offsets rather than an error; this test turns that into a failure.
"""

import pytest

try:
    import pyvex
except ImportError:
    pyvex = None

from archinfo import ArchAMD64


@pytest.mark.skipif(pyvex is None, reason="pyvex is not installed")
def test_all_registers_resolve_to_real_vex_offsets():
    arch = ArchAMD64()
    synthetic_base = max(pyvex.vex_ffi.guest_offsets.values()) + arch.bits
    bad = [reg.name for reg in arch.register_list if reg.vex_offset is None or reg.vex_offset >= synthetic_base]
    assert not bad, f"registers fell back to synthetic VEX offsets: {bad}"


@pytest.mark.skipif(pyvex is None, reason="pyvex is not installed")
def test_key_registers_match_pyvex_guest_offsets():
    arch = ArchAMD64()
    offsets = pyvex.vex_ffi.guest_offsets
    for name in ["rax", "rip", "sseround", "zmm0", "zmm31", "k0", "k7", "ftop", "fpround", "gs"]:
        vex_name = {"gs": "gs_const"}.get(name, name)
        assert arch.registers[name][0] == offsets[("amd64", vex_name)], name


@pytest.mark.skipif(pyvex is None, reason="pyvex is not installed")
def test_zmm_subregister_layout():
    arch = ArchAMD64()
    for i in range(32):
        base = arch.registers[f"zmm{i}"][0]
        assert arch.registers[f"zmm{i}"] == (base, 64)
        assert arch.registers[f"ymm{i}"] == (base, 32)
        assert arch.registers[f"xmm{i}"] == (base, 16)
        assert arch.registers[f"xmm{i}hq"] == (base + 8, 8)
    # the mask registers are consecutive 8-byte slots
    k0 = arch.registers["k0"][0]
    for i in range(8):
        assert arch.registers[f"k{i}"] == (k0 + 8 * i, 8)
