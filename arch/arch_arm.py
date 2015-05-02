import capstone as _capstone

from .arch import Arch

# TODO: determine proper base register (if it exists)
# TODO: handle multiple return registers?
# TODO: which endianness should be default?

class ArchARM(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchARM, self).__init__(endness)
        if endness == 'Iend_BE':
            self.function_prologs = {
                r"\xe9\x2d[\x00-\xff][\x00-\xff]",          # stmfd sp!, {xxxxx}
                r"\xe5\x2d\xe0\x04",                        # push {lr}
            }
            self.function_epilogs = {
                r"\xe8\xbd[\x00-\xff]{2}\xe1\x2f\xff\x1e"   # pop {xxx}; bx lr
                r"\xe4\x9d\xe0\x04\xe1\x2f\xff\x1e"         # pop {xxx}; bx lr
            }

    # ArchARM will match with any ARM, but ArchARMEL/ArchARMHF is a mismatch
    def __eq__(self, other):
        if not isinstance(other, ArchARM):
            return False
        if self.memory_endness != other.memory_endness or self.bits != other.bits:
            return False
        if type(self) == type(other):
            return True
        if type(self) is ArchARM or type(other) is ArchARM:
            return True
        return False

    @property
    def capstone(self):
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_ARM)
            self._cs.detail = True
        return self._cs

    @property
    def capstone_thumb(self):
        if self._cs_thumb is None:
            self._cs_thumb = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_THUMB)
            self._cs_thumb.detail = True
        return self._cs_thumb


    bits = 32
    vex_arch = "VexArchARM"
    name = "ARMEL"
    qemu_name = 'arm'
    ida_processor = 'armb'
    linux_name = 'arm'
    triplet = 'arm-linux-gnueabihf'
    max_inst_bytes = 4
    ip_offset = 68
    sp_offset = 60
    bp_offset = 60
    ret_offset = 8
    call_pushes_ret = False
    stack_change = -4
    memory_endness = 'Iend_LE'
    register_endness = 'Iend_LE'
    cs_arch = _capstone.CS_ARCH_ARM
    cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_thumb = None
    #self.ret_instruction = "\x0E\xF0\xA0\xE1" # this is mov pc, lr
    ret_instruction = "\x1E\xFF\x2F\xE1" # this is bx lr
    nop_instruction = "\x00\x00\x00\x00"
    function_prologs = {
        r"[\x00-\xff][\x00-\xff]\x2d\xe9",          # stmfd sp!, {xxxxx}
        r"\x04\xe0\x2d\xe5",                        # push {lr}
    }
    function_epilogs = {
        r"[\x00-\xff]{2}\xbd\xe8\x1e\xff\x2f\xe1"   # pop {xxx}; bx lr
        r"\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1"         # pop {xxx}; bx lr
    }
    instruction_alignment = 4
    concretize_unique_registers = {64}
    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ),      # the stack
        ( 0x188, 0x00000000, False, None )              # part of the thumb conditional flags
    ]
    entry_register_values = {
        'r0': 'ld_destructor'
    }

    default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc' ]

    register_names = {
        8: 'r0',
        12: 'r1',
        16: 'r2',
        20: 'r3',
        24: 'r4',
        28: 'r5',
        32: 'r6',
        36: 'r7',
        40: 'r8',
        44: 'r9',
        48: 'r10',
        52: 'r11',
        56: 'r12',

        # stack pointer
        60: 'sp',

        # link register
        64: 'lr',

        # program counter
        68: 'pc',

        # condition stuff
        72: 'cc_op',
        76: 'cc_dep1',
        80: 'cc_dep2',
        84: 'cc_ndep'
    }

    registers = {
        # GPRs
        'r0': (8, 4),
        'r1': (12, 4),
        'r2': (16, 4),
        'r3': (20, 4),
        'r4': (24, 4),
        'r5': (28, 4),
        'r6': (32, 4),
        'r7': (36, 4),
        'r8': (40, 4),
        'r9': (44, 4),
        'r10': (48, 4),
        'r11': (52, 4),
        'r12': (56, 4),

        # stack pointer
        'sp': (60, 4), 'bp': (60, 4),
        'r13': (60, 4),

        # link register
        'r14': (64, 4),
        'lr': (64, 4),

        # program counter
        'r15': (68, 4),
        'pc': (68, 4),
        'ip': (68, 4),

        # condition stuff
        'cc_op': (72, 4),
        'cc_dep1': (76, 4),
        'cc_dep2': (80, 4),
        'cc_ndep': (84, 4)
    }

    argument_registers = {
        registers['r0'][0],
        registers['r1'][0],
        registers['r2'][0],
        registers['r3'][0],
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0],
        registers['r11'][0],
        registers['r12'][0]
    }

    reloc_s_a = [2]
    reloc_b_a = [21]
    # R_ARM_TLS_DTPMOD32
    reloc_tls_mod_id = [17]
    # R_ARM_TLS_DTPOFF32 R_ARM_TLS_TPOFF32
    reloc_tls_offset = [18,19]
    got_section_name = '.got'

class ArchARMHF(ArchARM):
    name = 'ARMHF'
    triplet = 'arm-linux-gnueabihf'

class ArchARMEL(ArchARM):
    name = 'ARMEL'
    triplet = 'arm-linux-gnueabi'
