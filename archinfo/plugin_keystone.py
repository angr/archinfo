import logging
import keystone

from .plugin import ArchPlugin
from .arch import Arch, Endness
from .archerror import ArchError
from .arch_aarch64 import ArchAArch64
from .arch_amd64 import ArchAMD64
from .arch_arm import ArchARM, ArchARMCortexM
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64
from .arch_ppc32 import ArchPPC32
from .arch_ppc64 import ArchPPC64
from .arch_s390x import ArchS390X
from .arch_x86 import ArchX86

log = logging.getLogger(__name__)


class KeystonePlugin(ArchPlugin, patches=Arch):
    ks_arch = None
    ks_mode = None
    _ks = None

    @classmethod
    def _init_1(cls, arch):
        if arch.ks_mode is not None and arch.instruction_endness == Endness.BE:
            arch.ks_mode -= keystone.KS_MODE_LITTLE_ENDIAN
            arch.ks_mode += keystone.KS_MODE_BIG_ENDIAN

    @classmethod
    def _prep_getstate(cls, arch):
        arch._ks = None

    @classmethod
    def _prep_copy(cls, arch):
        arch._ks = None

    @property
    def keystone(self):
        """
        A Keystone instance for this arch
        """
        if self._ks is None:
            if self.ks_arch is None:
                raise ArchError("Arch %s does not support disassembly with Keystone" % self.name)
            self._ks = keystone.Ks(self.ks_arch, self.ks_mode)
            self._configure_keystone()
        return self._ks

    @property
    def keystone_thumb(self):
        raise ArchError("Arch %s does not support thumb mode" % self.name)

    @property
    def keystone_support(self):
        """
        Whether the architecture is supported by the Keystone engine or not.

        :return: True if this Arch is supported by the Keystone engine, False otherwise.
        :rtype:  bool
        """

        return self.ks_arch is not None

    def _configure_keystone(self):
        pass

    def asm(self, string, addr=0, as_bytes=True, thumb=False):
        """
        Compile the assembly instruction represented by string using Keystone

        :param string:     The textual assembly instructions, separated by semicolons
        :param addr:       The address at which the text should be assembled, to deal with PC-relative access. Default 0
        :param as_bytes:   Set to False to return a list of integers instead of a python byte string
        :param thumb:      If working with an ARM processor, set to True to assemble in thumb mode.
        :return:           The assembled bytecode
        """
        ks = self.keystone_thumb if thumb else self.keystone

        try:
            encoding, _ = ks.asm(string, addr, as_bytes)  # pylint: disable=too-many-function-args
        except TypeError:
            bytelist, _ = ks.asm(string, addr)
            if as_bytes:
                encoding = bytes(bytelist)
            else:
                encoding = bytelist

        return encoding


class KeystoneAArch64(KeystonePlugin, patches=ArchAArch64):
    ks_arch = keystone.KS_ARCH_ARM64
    ks_mode = keystone.KS_MODE_LITTLE_ENDIAN


class KeystoneAMD64(KeystonePlugin, patches=ArchAMD64):
    ks_arch = keystone.KS_ARCH_X86
    ks_mode = keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN
    _ks_x86_syntax = None

    @property
    def keystone_x86_syntax(self):
        """
        The current syntax Keystone uses for x86. It can be 'intel',
        'at&t', 'nasm', 'masm', 'gas' or 'radix16'
        """
        return self._ks_x86_syntax

    @keystone_x86_syntax.setter
    def keystone_x86_syntax(self, new_syntax):
        if new_syntax not in ("intel", "at&t", "nasm", "masm", "gas", "radix16"):
            raise ArchError(
                "Unsupported Keystone x86 syntax. It must be one of the following: "
                '"intel", "at&t", "nasm", "masm", "gas" or "radix16".'
            )

        if new_syntax != self._ks_x86_syntax:
            self._ks = None
            self._ks_x86_syntax = new_syntax

    def _configure_keystone(self):
        if self._ks_x86_syntax == "at&t":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        elif self._ks_x86_syntax == "nasm":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_NASM
        elif self._ks_x86_syntax == "masm":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_MASM
        elif self._ks_x86_syntax == "gas":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_GAS
        elif self._ks_x86_syntax == "radix16":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_RADIX16
        else:
            self._ks.syntax = keystone.KS_OPT_SYNTAX_INTEL


class KeystoneARM(KeystonePlugin, patches=ArchARM):
    ks_arch = keystone.KS_ARCH_ARM
    ks_mode = keystone.KS_MODE_ARM + keystone.KS_MODE_LITTLE_ENDIAN
    _ks_thumb = None

    @property
    def keystone_thumb(self):
        if self._ks_thumb is None:
            self._ks_thumb = keystone.Ks(self.ks_arch, keystone.KS_MODE_THUMB)
        return self._ks_thumb


class KeystoneARMCortexM(KeystonePlugin, patches=ArchARMCortexM):
    ks_arch = keystone.KS_ARCH_ARM
    ks_mode = keystone.KS_MODE_THUMB + keystone.KS_MODE_LITTLE_ENDIAN

    @property
    def keystone_thumb(self):
        return self.keystone


class KeystoneMIPS32(KeystonePlugin, patches=ArchMIPS32):
    ks_arch = keystone.KS_ARCH_MIPS
    ks_mode = keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN


class KeystoneMIPS64(KeystonePlugin, patches=ArchMIPS64):
    ks_arch = keystone.KS_ARCH_MIPS
    ks_mode = keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN


class KeystonePPC32(KeystonePlugin, patches=ArchPPC32):
    ks_arch = keystone.KS_ARCH_PPC
    ks_mode = keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN


class KeystonePPC64(KeystonePlugin, patches=ArchPPC64):
    ks_arch = keystone.KS_ARCH_PPC
    ks_mode = keystone.KS_MODE_64 + keystone.KS_MODE_LITTLE_ENDIAN


class KeystoneS390X(KeystonePlugin, patches=ArchS390X):
    ks_arch = keystone.KS_ARCH_SYSTEMZ
    ks_mode = keystone.KS_MODE_BIG_ENDIAN


class KeystoneX86(KeystonePlugin, patches=ArchX86):
    _ks_x86_syntax = None
    ks_arch = keystone.KS_ARCH_X86
    ks_mode = keystone.KS_MODE_32 + keystone.KS_MODE_LITTLE_ENDIAN

    @property
    def keystone_x86_syntax(self):
        """
        Get the current syntax Keystone uses for x86. It can be 'intel',
        'at&t', 'nasm', 'masm', 'gas' or 'radix16'

        :return: Keystone's current x86 syntax
        :rtype: str
        """

        return self._ks_x86_syntax

    @keystone_x86_syntax.setter
    def keystone_x86_syntax(self, new_syntax):
        """
        Set the syntax that Keystone uses for x86.
        """

        if new_syntax not in ("intel", "at&t", "nasm", "masm", "gas", "radix16"):
            raise ArchError(
                "Unsupported Keystone x86 syntax. It must be one of the following: "
                '"intel", "at&t", "nasm", "masm", "gas" or "radix16".'
            )

        if new_syntax != self._ks_x86_syntax:
            self._ks = None
            self._ks_x86_syntax = new_syntax

    def _configure_keystone(self):
        if self._ks_x86_syntax == "at&t":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        elif self._ks_x86_syntax == "nasm":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_NASM
        elif self._ks_x86_syntax == "masm":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_MASM
        elif self._ks_x86_syntax == "gas":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_GAS
        elif self._ks_x86_syntax == "radix16":
            self._ks.syntax = keystone.KS_OPT_SYNTAX_RADIX16
        else:
            self._ks.syntax = keystone.KS_OPT_SYNTAX_INTEL
