import logging
import keystone

from .plugin import ArchPlugin
from .archerror import ArchError

log = logging.getLogger(__name__)


class KeystonePlugin(ArchPlugin):
    ks_arch = None
    ks_mode = None
    _ks = None

    @classmethod
    def _fill_1(cls, arch, endness, instruction_endness):
        if arch.ks_mode is not None:
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
            if keystone is None:
                raise Exception("Keystone is not installed!")
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
