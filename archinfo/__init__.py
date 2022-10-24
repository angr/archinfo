"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = "9.2.24.dev0"

# pylint: disable=wildcard-import
from .arch import *
from .arch_aarch64 import ArchAArch64
from .arch_amd64 import ArchAMD64
from .arch_arm import ArchARM, ArchARMCortexM, ArchARMEL, ArchARMHF
from .arch_avr import ArchAVR8
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64
from .arch_ppc32 import ArchPPC32
from .arch_ppc64 import ArchPPC64
from .arch_s390x import ArchS390X
from .arch_soot import ArchSoot
from .arch_x86 import ArchX86
from .archerror import ArchError
from .defines import defines
from .types import RegisterName, RegisterOffset, TmpVar
