import unicorn

from .plugin import ArchPlugin, Arch
from .archerror import ArchError
from .register import Endness
from .arch_aarch64 import ArchAArch64
from .arch_amd64 import ArchAMD64
from .arch_arm import ArchARM, ArchARMCortexM
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64
from .arch_x86 import ArchX86


class UnicornPlugin(ArchPlugin, patches=Arch):
    uc_arch = None
    uc_mode = None
    uc_const = None
    uc_prefix = None
    uc_regs = None

    @classmethod
    def _init_2(cls, arch):
        # Unicorn specific stuff
        if arch.uc_mode is not None:
            if arch.instruction_endness == Endness.BE:
                arch.uc_mode -= unicorn.UC_MODE_LITTLE_ENDIAN
                arch.uc_mode += unicorn.UC_MODE_BIG_ENDIAN
            arch.uc_regs = {}
            # map register names to Unicorn const
            for r in arch.register_names.values():
                reg_name = arch.uc_prefix + "REG_" + r.upper()
                if hasattr(arch.uc_const, reg_name):
                    arch.uc_regs[r] = getattr(arch.uc_const, reg_name)

    @property
    def unicorn(self):
        """
        A Unicorn engine instance for this arch
        """
        if self.uc_arch is None:
            raise ArchError("Arch %s does not support with Unicorn" % self.name)
        # always create a new Unicorn instance
        return unicorn.Uc(self.uc_arch, self.uc_mode)

    def unicorn_support(self):
        """
        Whether the architecture is supported by Unicorn engine or not,

        :return: True if this Arch is supported by the Unicorn engine, False otherwise.
        :rtype:  bool
        """

        return self.qemu_name is not None


class UnicornAArch64(UnicornPlugin, patches=ArchAArch64):
    uc_arch = unicorn.UC_ARCH_ARM64
    uc_mode = unicorn.UC_MODE_LITTLE_ENDIAN
    uc_const = unicorn.arm64_const
    uc_prefix = "UC_ARM64_"


class UnicornAMD64(UnicornPlugin, patches=ArchAMD64):
    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN
    uc_const = unicorn.x86_const
    uc_prefix = "UC_X86_"


class UnicornARM(UnicornPlugin, patches=ArchARM):
    uc_arch = unicorn.UC_ARCH_ARM
    uc_mode = unicorn.UC_MODE_LITTLE_ENDIAN
    uc_mode_thumb = unicorn.UC_MODE_LITTLE_ENDIAN + unicorn.UC_MODE_THUMB
    uc_const = unicorn.arm_const
    uc_prefix = "UC_ARM_"

    @property
    def unicorn_thumb(self):
        return unicorn.Uc(self.uc_arch, self.uc_mode + unicorn.UC_MODE_THUMB)


class UnicornARMCortexM(UnicornARM, patches=ArchARMCortexM):
    uc_arch = unicorn.UC_ARCH_ARM
    uc_mode = unicorn.UC_MODE_THUMB + unicorn.UC_MODE_LITTLE_ENDIAN
    uc_mode_thumb = unicorn.UC_MODE_THUMB + unicorn.UC_MODE_LITTLE_ENDIAN


class UnicornMIPS32(UnicornPlugin, patches=ArchMIPS32):
    uc_arch = unicorn.UC_ARCH_MIPS
    uc_mode = unicorn.UC_MODE_32 + unicorn.UC_MODE_LITTLE_ENDIAN
    uc_const = unicorn.mips_const
    uc_prefix = "UC_MIPS_"


class UnicornMIPS64(UnicornPlugin, patches=ArchMIPS64):
    uc_arch = unicorn.UC_ARCH_MIPS
    uc_mode = unicorn.UC_MODE_64 + unicorn.UC_MODE_LITTLE_ENDIAN
    uc_const = unicorn.mips_const
    uc_prefix = "UC_MIPS_"


class UnicornX86(UnicornPlugin, patches=ArchX86):
    uc_arch = unicorn.UC_ARCH_X86
    uc_mode = unicorn.UC_MODE_32 + unicorn.UC_MODE_LITTLE_ENDIAN
    uc_const = unicorn.x86_const
    uc_prefix = "UC_X86_"
