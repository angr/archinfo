import unicorn

from .plugin import ArchPlugin
from .archerror import ArchError
from .register import Endness


class UnicornPlugin(ArchPlugin):
    uc_arch = None
    uc_mode = None
    uc_const = None
    uc_prefix = None
    uc_regs = None

    @classmethod
    def _fill_2(cls, arch, endness, instruction_endness):
        # Unicorn specific stuff
        if arch.uc_mode is not None:
            if endness == Endness.BE:
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
