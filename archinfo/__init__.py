"""
archinfo is a collection of classes that contain architecture-specific information.
It is useful for cross-architecture tools (such as pyvex).
"""

__version__ = "9.2.35.dev0"


from .arch import (
    RegisterOffset,
    TmpVar,
    RegisterName,
    Endness,
    Register,
    Arch,
    register_arch,
    ArchNotFound,
    arch_from_id,
    reverse_ends,
    get_host_arch,
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

__all__ = (
    __version__,
    RegisterOffset,
    TmpVar,
    RegisterName,
    Endness,
    Register,
    Arch,
    register_arch,
    ArchNotFound,
    arch_from_id,
    reverse_ends,
    get_host_arch,
    defines,
    ArchAMD64,
    ArchX86,
    ArchARM,
    ArchARMEL,
    ArchARMHF,
    ArchARMCortexM,
    ArchAArch64,
    ArchAVR8,
    ArchPPC32,
    ArchPPC64,
    ArchMIPS32,
    ArchMIPS64,
    ArchSoot,
    ArchError,
    ArchS390X,
)
