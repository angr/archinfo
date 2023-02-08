import logging
import capstone

from .archerror import ArchError
from .plugin import ArchPlugin
from .arch import Arch
from .arch_amd64 import ArchAMD64
from .arch_x86 import ArchX86
from .arch_arm import ArchARM, ArchARMCortexM
from .arch_aarch64 import ArchAArch64

log = logging.getLogger(__name__)


class CapstonePlugin(ArchPlugin, patches=Arch):
    cs_arch = None
    cs_mode = None
    _cs = None
    _cs_thumb = None

    @classmethod
    def _init(cls, arch, endness, instruction_endness):
        if arch.cs_mode is not None:
            arch.cs_mode -= capstone.CS_MODE_LITTLE_ENDIAN
            arch.cs_mode += capstone.CS_MODE_BIG_ENDIAN
        arch._cs = None
        arch._cs_thumb = None

    @classmethod
    def _prep_getstate(cls, arch):
        arch._cs = None
        arch._cs_thumb = None

    @classmethod
    def _prep_copy(cls, arch):
        arch._cs = None
        arch._cs_thumb = None

    @property
    def capstone(self: Arch):
        """
        A Capstone instance for this arch
        """
        if self.cs_arch is None:
            raise ArchError("Arch %s does not support disassembly with Capstone" % self.name)
        if self._cs is None:
            self._cs = capstone.Cs(self.cs_arch, self.cs_mode)
            self._configure_capstone()
            self._cs.detail = True
        return self._cs

    @property
    def capstone_support(self):
        """
        Whether the architecture is supported by the Capstone engine or not.

        :return: True if this Arch is supported by the Capstone engine, False otherwise.
        :rtype:  bool
        """

        return self.cs_arch is not None

    @property
    def capstone_thumb(self: Arch):
        raise ArchError("Arch %s does not support thumb mode" % self.name)

    def _configure_capstone(self):
        pass

    def disasm(self, bytestring, addr=0, thumb=False):
        if thumb and not hasattr(self, "capstone_thumb"):
            log.warning("Specified thumb=True on non-ARM architecture")
            thumb = False
        cs = self.capstone_thumb if thumb else self.capstone  # pylint: disable=no-member
        return "\n".join(f"{insn.address:#x}:\t{insn.mnemonic} {insn.op_str}" for insn in cs.disasm(bytestring, addr))


class CapstoneAMD64(CapstonePlugin, patches=ArchAMD64):
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64 + capstone.CS_MODE_LITTLE_ENDIAN

    @classmethod
    def _init(cls, arch, endness, instruction_endness):
        super()._init(arch, endness, instruction_endness)

        arch._cs_x86_syntax = None

    @property
    def capstone_x86_syntax(self):
        """
        The current syntax Capstone uses for x64. It can be 'intel' or 'at&t'
        """
        return self._cs_x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax):
        if new_syntax not in ("intel", "at&t"):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._cs_x86_syntax:
            self._cs = None
            self._cs_x86_syntax = new_syntax

    def _configure_capstone(self):
        if self._cs_x86_syntax == "at&t":
            self._cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        else:
            self._cs.syntax = capstone.CS_OPT_SYNTAX_INTEL


class CapstoneX86(CapstonePlugin, patches=ArchX86):
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_32 + capstone.CS_MODE_LITTLE_ENDIAN

    @property
    def capstone_x86_syntax(self):
        """
        Get the current syntax Capstone uses for x86. It can be 'intel' or 'at&t'

        :return: Capstone's current x86 syntax
        :rtype: str
        """

        return self._cs_x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax):
        """
        Set the syntax that Capstone outputs for x86.
        """

        if new_syntax not in ("intel", "at&t"):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._cs_x86_syntax:
            self._cs = None
            self._cs_x86_syntax = new_syntax

    def _configure_capstone(self):
        self._cs.syntax = capstone.CS_OPT_SYNTAX_ATT if self._cs_x86_syntax == "at&t" else capstone.CS_OPT_SYNTAX_INTEL


class CapstoneARM(CapstonePlugin, patches=ArchARM):
    cs_arch = capstone.CS_ARCH_ARM
    cs_mode = capstone.CS_MODE_LITTLE_ENDIAN

    @property
    def capstone_thumb(self):
        if self._cs_thumb is None:
            self._cs_thumb = capstone.Cs(self.cs_arch, self.cs_mode + capstone.CS_MODE_THUMB)
            self._cs_thumb.detail = True
        return self._cs_thumb


class CapstoneARMCortexM(CapstoneARM, patches=ArchARMCortexM):
    cs_mode = capstone.CS_MODE_LITTLE_ENDIAN + capstone.CS_MODE_THUMB + capstone.CS_MODE_MCLASS

    @property
    def capstone_thumb(self):
        return self.capstone


class CapstoneAArch64(CapstonePlugin, patches=ArchAArch64):
    cs_arch = capstone.CS_ARCH_ARM64
    cs_mode = capstone.CS_MODE_LITTLE_ENDIAN
