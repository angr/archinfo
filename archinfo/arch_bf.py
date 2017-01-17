from .arch import Arch

class ArchBF(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchBF, self).__init__(endness)

        self.bits = 64
        self.vex_arch = None
        self.name = "BF"

        # Things I did not want to include but were necessary unfortunately :-(
        # self.cs_mode = capstone.CS_MODE_LITTLE_ENDIAN if endness == 'Iend_LE' else capstone.CS_MODE_BIG_ENDIAN
        # END

        self.registers = {}
        self.registers["pc"] =       (0, 1)
        self.registers["ptr"] =       (1, 1)
        self.registers["in"] =      (2, 1)
        self.registers["out"] =      (3, 1)

        self.register_names = {}
        self.register_names[self.registers['pc'][0]] = 'pc'

        self.ip_offset = self.registers["pc"][0]
