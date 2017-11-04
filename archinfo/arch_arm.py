try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch, register_arch, Endness
from .tls import TLSArchInfo

# TODO: determine proper base register (if it exists)
# TODO: handle multiple return registers?
# TODO: which endianness should be default?

class ArchARM(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchARM, self).__init__(endness)
        if endness == Endness.BE:
            self.function_prologs = {
                br"\xe9\x2d[\x00-\xff][\x00-\xff]",          # stmfd sp!, {xxxxx}
                br"\xe5\x2d\xe0\x04",                        # push {lr}
            }
            self.function_epilogs = {
                br"\xe8\xbd[\x00-\xff]{2}\xe1\x2f\xff\x1e"   # pop {xxx}; bx lr
                br"\xe4\x9d\xe0\x04\xe1\x2f\xff\x1e"         # pop {xxx}; bx lr
            }

    # ArchARM will match with any ARM, but ArchARMEL/ArchARMHF is a mismatch
    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        if not isinstance(other, ArchARM):
            return False
        if self.memory_endness != other.memory_endness or self.bits != other.bits:
            return False
        if type(self) is type(other):
            return True
        if type(self) is ArchARM or type(other) is ArchARM:
            return True
        return False

    def __getstate__(self):
        self._cs = None
        self._cs_thumb = None
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)

    @property
    def capstone(self):
        if self.cs_arch is None:
            raise ArchError("Arch %s does not support disassembly with capstone" % self.name)
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_ARM)
            self._cs.detail = True
        return self._cs

    @property
    def capstone_thumb(self):
        if self.cs_arch is None:
            raise ArchError("Arch %s does not support disassembly with capstone" % self.name)
        if self._cs_thumb is None:
            self._cs_thumb = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_THUMB)
            self._cs_thumb.detail = True
        return self._cs_thumb

    @property
    def unicorn(self):
        return _unicorn.Uc(self.uc_arch, self.uc_mode + _unicorn.UC_MODE_ARM) if _unicorn is not None else None

    @property
    def unicorn_thumb(self):
        return _unicorn.Uc(self.uc_arch, self.uc_mode + _unicorn.UC_MODE_THUMB) if _unicorn is not None else None

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
    lr_offset = 64
    vex_conditional_helpers = True
    syscall_num_offset = 36
    call_pushes_ret = False
    stack_change = -4
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_ARM
        cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_thumb = None
    uc_arch = _unicorn.UC_ARCH_ARM if _unicorn else None
    uc_mode = _unicorn.UC_MODE_LITTLE_ENDIAN if _unicorn else None
    uc_const = _unicorn.arm_const if _unicorn else None
    uc_prefix = "UC_ARM_" if _unicorn else None
    #self.ret_instruction = b"\x0E\xF0\xA0\xE1" # this is mov pc, lr
    ret_instruction = b"\x1E\xFF\x2F\xE1" # this is bx lr
    nop_instruction = b"\x00\x00\x00\x00"
    function_prologs = {
        br"[\x00-\xff][\x00-\xff]\x2d\xe9",          # stmfd sp!, {xxxxx}
        br"\x04\xe0\x2d\xe5",                        # push {lr}
    }
    function_epilogs = {
        br"[\x00-\xff]{2}\xbd\xe8\x1e\xff\x2f\xe1"   # pop {xxx}; bx lr
        br"\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1"         # pop {xxx}; bx lr
    }
    instruction_alignment = 2  # cuz there is also thumb mode
    concretize_unique_registers = {64}
    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ),      # the stack
        ( 'itstate', 0x00000000, False, None ),         # part of the thumb conditional flags
        ( 'cc_op', 0, False, None ),
        ( 'cc_dep1', 0, False, None ),
        ( 'cc_dep2', 0, False, None ),
        ( 'cc_ndep', 0, False, None ),
    ]
    entry_register_values = {
        'r0': 'ld_destructor'
    }

    default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                                   'sp', 'lr', 'pc' ]

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
        60: 'sp',
        64: 'lr',
        68: 'pc',
        72: 'cc_op',
        76: 'cc_dep1',
        80: 'cc_dep2',
        84: 'cc_ndep',
        88: 'qflag32',
        92: 'geflag0',
        96: 'geflag1',
        100: 'geflag2',
        104: 'geflag3',
        108: 'emnote',
        112: 'cmstart',
        116: 'cmlen',
        120: 'nraddr',
        124: 'ip_at_syscall',
        128: 'd0',
        136: 'd1',
        144: 'd2',
        152: 'd3',
        160: 'd4',
        168: 'd5',
        176: 'd6',
        184: 'd7',
        192: 'd8',
        200: 'd9',
        208: 'd10',
        216: 'd11',
        224: 'd12',
        232: 'd13',
        240: 'd14',
        248: 'd15',
        256: 'd16',
        264: 'd17',
        272: 'd18',
        280: 'd19',
        288: 'd20',
        296: 'd21',
        304: 'd22',
        312: 'd23',
        320: 'd24',
        328: 'd25',
        336: 'd26',
        344: 'd27',
        352: 'd28',
        360: 'd29',
        368: 'd30',
        376: 'd31',
        384: 'fpscr',
        388: 'tpidruro',
        392: 'itstate',
    }

    registers = {
        'r0': (8, 4),
        'r1': (12, 4),
        'r2': (16, 4),
        'r3': (20, 4),
        'r4': (24, 4),
        'r5': (28, 4),
        'r6': (32, 4),
        'r7': (36, 4),
        'r8': (40, 4),
        'sb': (44, 4),
        'r9': (44, 4),
        'sl': (48, 4),
        'r10': (48, 4),
        'fp': (52, 4),
        'r11': (52, 4),
        'r12': (56, 4),
        'bp': (60, 4),
        'r13': (60, 4),
        'sp': (60, 4),
        'lr': (64, 4),
        'r14': (64, 4),
        'ip': (68, 4),
        'pc': (68, 4),
        'r15': (68, 4),
        'r15t': (68, 4),
        'cc_op': (72, 4),
        'cc_dep1': (76, 4),
        'cc_dep2': (80, 4),
        'cc_ndep': (84, 4),
        'qflag32': (88, 4),
        'geflag0': (92, 4),
        'geflag1': (96, 4),
        'geflag2': (100, 4),
        'geflag3': (104, 4),
        'emnote': (108, 4),
        'cmstart': (112, 4),
        'cmlen': (116, 4),
        'nraddr': (120, 4),
        'ip_at_syscall': (124, 4),
        'd0': (128, 8),
        'd1': (136, 8),
        'd2': (144, 8),
        'd3': (152, 8),
        'd4': (160, 8),
        'd5': (168, 8),
        'd6': (176, 8),
        'd7': (184, 8),
        'd8': (192, 8),
        'd9': (200, 8),
        'd10': (208, 8),
        'd11': (216, 8),
        'd12': (224, 8),
        'd13': (232, 8),
        'd14': (240, 8),
        'd15': (248, 8),
        'd16': (256, 8),
        'd17': (264, 8),
        'd18': (272, 8),
        'd19': (280, 8),
        'd20': (288, 8),
        'd21': (296, 8),
        'd22': (304, 8),
        'd23': (312, 8),
        'd24': (320, 8),
        'd25': (328, 8),
        'd26': (336, 8),
        'd27': (344, 8),
        'd28': (352, 8),
        'd29': (360, 8),
        'd30': (368, 8),
        'd31': (376, 8),
        'fpscr': (384, 4),
        'tpidruro': (388, 4),
        'itstate': (392, 4),
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

    got_section_name = '.got'
    ld_linux_name = 'ld-linux.so.3'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)
    #elf_tls = TLSArchInfo(1, 32, [], [0], [], 0, 0)
    # that line was lying in the original CLE code and I have no clue why it's different

class ArchARMHF(ArchARM):
    name = 'ARMHF'
    triplet = 'arm-linux-gnueabihf'
    ld_linux_name = 'ld-linux-armhf.so.3'

class ArchARMEL(ArchARM):
    name = 'ARMEL'
    triplet = 'arm-linux-gnueabi'
    ld_linux_name = 'ld-linux.so.3'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

register_arch([r'.*armhf.*'], 32, 'any', ArchARMHF)
register_arch([r'.*armeb|.*armbe'], 32, Endness.BE, ArchARM)
register_arch([r'.*armel|arm.*'], 32, Endness.LE, ArchARMEL)
register_arch([r'.*arm.*|.*thumb.*'], 32, 'any', ArchARM)
