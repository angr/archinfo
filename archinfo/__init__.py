# pylint: disable=wrong-import-position
"""
archinfo is a collection of classes that contain architecture-specific information.
at is useful for cross-architecture tools (such as pyvex).
"""

__version__ = "9.2.41.dev0"


from typing import Optional, Type

from .types import RegisterOffset, TmpVar, RegisterName
from .arch import (
    Endness,
    Register,
    Arch,
    register_arch,
    ArchNotFound,
    arch_from_id,
    reverse_ends,
    get_host_arch,
    all_arches,
)
from .defines import defines
from .arch_amd64 import ArchAMD64
from .arch_x86 import ArchX86
from .arch_arm import ArchARM, ArchARMEL, ArchARMHF, ArchARMCortexM
from .arch_aarch64 import ArchAArch64
from .arch_avr import ArchAVR8
from .arch_ppc32 import ArchPPC32
from .arch_ppc64 import ArchPPC64
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64
from .arch_soot import ArchSoot
from .archerror import ArchError
from .arch_s390x import ArchS390X
from .plugin import ArchPlugin

ArchPcode: Optional[Type[Arch]]
PyvexPlugin: Optional[Type[ArchPlugin]]
CapstonePlugin: Optional[Type[ArchPlugin]]
KeystonePlugin: Optional[Type[ArchPlugin]]
UnicornPlugin: Optional[Type[ArchPlugin]]
PyvexUnicornPlugin: Optional[Type[ArchPlugin]]

try:
    from .arch_pcode import ArchPcode
except ModuleNotFoundError:
    ArchPcode = None

try:
    from .plugin_pyvex import PyvexPlugin
except ModuleNotFoundError:
    PyvexPlugin = None

try:
    from .plugin_capstone import CapstonePlugin
except ModuleNotFoundError:
    CapstonePlugin = None

try:
    from .plugin_keystone import KeystonePlugin
except ModuleNotFoundError:
    KeystonePlugin = None

try:
    from .plugin_unicorn import UnicornPlugin
except ModuleNotFoundError:
    UnicornPlugin = None

try:
    from .plugin_pyvex_unicorn import PyvexUnicornPlugin
except ModuleNotFoundError:
    PyvexUnicornPlugin = None

__all__ = [
    "RegisterOffset",
    "TmpVar",
    "RegisterName",
    "Endness",
    "Register",
    "Arch",
    "register_arch",
    "ArchNotFound",
    "arch_from_id",
    "reverse_ends",
    "get_host_arch",
    "all_arches",
    "defines",
    "ArchAMD64",
    "ArchX86",
    "ArchARM",
    "ArchARMEL",
    "ArchARMHF",
    "ArchARMCortexM",
    "ArchAArch64",
    "ArchAVR8",
    "ArchPPC32",
    "ArchPPC64",
    "ArchMIPS32",
    "ArchMIPS64",
    "ArchSoot",
    "ArchError",
    "ArchS390X",
    "ArchPcode",
    "PyvexPlugin",
    "CapstonePlugin",
    "KeystonePlugin",
    "UnicornPlugin",
    "PyvexUnicornPlugi",
    "ArchPlugin",
]
