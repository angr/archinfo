# pylint: disable=wrong-import-position
"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = "9.3.4.dev0"


import contextlib

from .arch import (
    Arch,
    ArchNotFound,
    Register,
    all_arches,
    get_host_arch,
    register_arch,
    reverse_ends,
)
from .arch import arch_from_id as _arch_from_id
from .arch_aarch64 import ArchAArch64
from .arch_amd64 import ArchAMD64
from .arch_arm import ArchARM, ArchARMCortexM, ArchARMEL, ArchARMHF
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64, ArchMIPSN32
from .arch_pcode import ArchPcode
from .arch_ppc32 import ArchPPC32
from .arch_ppc64 import ArchPPC64
from .arch_riscv64 import ArchRISCV64
from .arch_s390x import ArchS390X
from .arch_soot import ArchSoot
from .arch_x86 import ArchX86
from .archerror import ArchError
from .types import Endness, RegisterName, RegisterOffset, TmpVar

__all__ = [
    "Arch",
    "ArchAArch64",
    "ArchAMD64",
    "ArchARM",
    "ArchARMCortexM",
    "ArchARMEL",
    "ArchARMHF",
    "ArchError",
    "ArchMIPS32",
    "ArchMIPS64",
    "ArchMIPSN32",
    "ArchNotFound",
    "ArchPPC32",
    "ArchPPC64",
    "ArchPcode",
    "ArchRISCV64",
    "ArchS390X",
    "ArchSoot",
    "ArchX86",
    "Endness",
    "Register",
    "RegisterName",
    "RegisterOffset",
    "TmpVar",
    "all_arches",
    "arch_from_id",
    "get_host_arch",
    "register_arch",
    "reverse_ends",
]


def arch_from_id(ident: str, endness: str = Endness.ANY, bits: str | int = "") -> Arch:
    """
    Take our best guess at the arch referred to by the given identifier, and return an instance of its class.

    You may optionally provide the ``endness`` and ``bits`` parameters to help this function out. ``bits`` is
    either a number of bits or a string containing one, which is what an ELF class is.

    A full sleigh language id, such as ``pa-risc:BE:32:default``, returns the ArchPcode for that language. It
    carries its own endness and width, so the ``endness`` and ``bits`` hints do not apply to it.
    """
    # A language id names one language, so it answers before the registered architectures, whose regexes
    # would otherwise claim ARM:LE:32:v7 for ArchARMEL.
    if ":" in ident:
        with contextlib.suppress(ArchError):
            return ArchPcode(ident)

    return _arch_from_id(ident, endness, bits)
