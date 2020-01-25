"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = (8, 20, 1, 7)

if bytes is str:
    raise Exception("This module is designed for python 3 only. Please install an older version to use python 2.")

# Type Aliases
from typing import NewType
RegisterOffset = NewType('RegisterOffset', int)
RegisterName = NewType('RegisterName', str)
TmpVar = NewType('TmpVar', int)

# pylint: disable=wildcard-import
from .arch import *
from .defines import defines
from .arch_amd64    import ArchAMD64
from .arch_x86      import ArchX86
from .arch_arm      import ArchARM, ArchARMEL, ArchARMHF, ArchARMCortexM
from .arch_aarch64  import ArchAArch64
from .arch_ppc32    import ArchPPC32
from .arch_ppc64    import ArchPPC64
from .arch_mips32   import ArchMIPS32
from .arch_mips64   import ArchMIPS64
from .arch_soot     import ArchSoot
from .archerror     import ArchError
from .arch_s390x    import ArchS390X
