"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = (8, 20, 6, 1)

if bytes is str:
    raise Exception("This module is designed for python 3 only. Please install an older version to use python 2.")

# NewType Declaration, see https://docs.python.org/3/library/typing.html#newtype
from typing import NewType
RegisterOffset = NewType('RegisterOffset', int)
TmpVar = NewType('TmpVar', int)

# This causes too much issues as a NewType, sot is a simple alias instead
# This means that is still legal to pass any str where a RegisterName is expected.
# The downside is that PyCharm will show the type as `str` when displaying the signature
RegisterName = str



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
