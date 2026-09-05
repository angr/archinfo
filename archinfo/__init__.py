# pylint: disable=wrong-import-position
"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = "9.3.5.dev0"


import contextlib
import platform as _platform
import re

from .arch import (
    Arch,
    ArchNotFound,
    Register,
    all_arches,
    arch_id_map,
    register_arch,
    reverse_ends,
)
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

    if bits == 64 or (isinstance(bits, str) and "64" in bits):
        bits = 64
    elif isinstance(bits, str) and "32" in bits:
        bits = 32
    elif not bits and "64" in ident:
        bits = 64
    elif not bits and "32" in ident:
        bits = 32

    endness = endness.lower()
    if "lit" in endness:
        endness = Endness.LE
    elif "big" in endness:
        endness = Endness.BE
    elif "lsb" in endness:
        endness = Endness.LE
    elif "msb" in endness:
        endness = Endness.BE
    elif "le" in endness:
        endness = Endness.LE
    elif "be" in endness:
        endness = Endness.BE
    elif "l" in endness:
        endness = Endness.UNSURE
    elif "b" in endness:
        endness = Endness.UNSURE
    else:
        endness = Endness.UNSURE
    ident = ident.lower()
    cls = None
    aendness = None
    for arxs, abits, aendness, acls in arch_id_map:
        found_it = False
        for rx in arxs:
            if re.search(rx, ident):
                found_it = True
                break
        if not found_it:
            continue
        if bits and bits != abits:
            continue
        if aendness == Endness.ANY or endness == aendness or endness == Endness.UNSURE:
            cls = acls
            break
    if not cls:
        raise ArchNotFound(
            f"Can't find architecture info for architecture {ident} with {repr(bits)} bits and {endness} endness"
        )
    if endness == Endness.UNSURE:
        if aendness == Endness.ANY:
            # We really don't care, use default
            return cls(cls.default_endness)
        else:
            # We're expecting the ident to pick the endness.
            # ex. 'armeb' means obviously this is Iend_BE
            return cls(aendness)
    else:
        return cls(endness)


def get_host_arch():
    """
    Return the arch of the machine we are currently running on.
    """
    return arch_from_id(_platform.machine())


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
