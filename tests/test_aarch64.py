from __future__ import annotations

import pytest

from archinfo import ArchAArch64


def test_unicorn_stack_pointer_mapping():
    unicorn = pytest.importorskip("unicorn")
    arch = ArchAArch64()
    unicorn_sp = unicorn.arm64_const.UC_ARM64_REG_SP

    assert arch.uc_regs["xsp"] == unicorn_sp
    assert arch.vex_to_unicorn_map[arch.sp_offset] == (unicorn_sp, arch.bytes)
