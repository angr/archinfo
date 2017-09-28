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

class ArchAArch64(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchAArch64, self).__init__(endness)
        if endness == Endness.BE:
            self.ida_processor = 'armb'
            self.function_prologs = set((
                # TODO
            ))
            self.function_epilogs = set((
                # TODO
            ))

    bits = 64
    vex_arch = "VexArchARM64"
    name = "AARCH64"
    qemu_name = 'aarch64'
    ida_processor = 'arm'
    linux_name = 'aarch64'
    triplet = 'aarch64-linux-gnueabihf'
    max_inst_bytes = 4
    ip_offset = 272
    sp_offset = 264
    bp_offset = 248
    ret_offset = 16
    lr_offset = 256
    vex_conditional_helpers = True
    syscall_num_offset = 80
    call_pushes_ret = False
    stack_change = -8
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_ARM64
        cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_ARM64 if _unicorn else None
    uc_mode = _unicorn.UC_MODE_LITTLE_ENDIAN if _unicorn else None
    uc_const = _unicorn.arm64_const if _unicorn else None
    uc_prefix = "UC_ARM64_" if _unicorn else None
    initial_sp = 0x7ffffffffff0000

    ret_instruction = b"\xC0\x03\x5F\xD6"    # ret
    nop_instruction = b"\x1F\x20\x03\xD5"    # nop
    function_prologs = set((
        #r"\xFD\x7B\xBE\xA9\xFD\x03\x00\x91"
        # TODO
    ))
    function_epilogs = set((
        # TODO
    ))
    instruction_alignment = 4
    concretize_unique_registers = set()
    default_register_values = [
        ( 'sp', initial_sp, True, 'global' ),        # the stack
        ( 'fpcr', 0, False, None)
    ]
    entry_register_values = {
        'x0': 'ld_destructor'
    }

    default_symbolic_registers = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12',
                                  'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23', 'x24',
                                  'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31']

    register_names = {
        16: 'x0',
        24: 'x1',
        32: 'x2',
        40: 'x3',
        48: 'x4',
        56: 'x5',
        64: 'x6',
        72: 'x7',
        80: 'x8',
        88: 'x9',
        96: 'x10',
        104: 'x11',
        112: 'x12',
        120: 'x13',
        128: 'x14',
        136: 'x15',
        144: 'x16',
        152: 'x17',
        160: 'x18',
        168: 'x19',
        176: 'x20',
        184: 'x21',
        192: 'x22',
        200: 'x23',
        208: 'x24',
        216: 'x25',
        224: 'x26',
        232: 'x27',
        240: 'x28',
        248: 'x29',
        256: 'x30',
        264: 'xsp',
        272: 'pc',
        280: 'cc_op',
        288: 'cc_dep1',
        296: 'cc_dep2',
        304: 'cc_ndep',
        312: 'tpidr_el0',
        320: 'q0',
        336: 'q1',
        352: 'q2',
        368: 'q3',
        384: 'q4',
        400: 'q5',
        416: 'q6',
        432: 'q7',
        448: 'q8',
        464: 'q9',
        480: 'q10',
        496: 'q11',
        512: 'q12',
        528: 'q13',
        544: 'q14',
        560: 'q15',
        576: 'q16',
        592: 'q17',
        608: 'q18',
        624: 'q19',
        640: 'q20',
        656: 'q21',
        672: 'q22',
        688: 'q23',
        704: 'q24',
        720: 'q25',
        736: 'q26',
        752: 'q27',
        768: 'q28',
        784: 'q29',
        800: 'q30',
        816: 'q31',
        832: 'qcflag',
        848: 'emnote',
        856: 'cmstart',
        864: 'cmlen',
        872: 'nraddr',
        880: 'ip_at_syscall',
        888: 'fpcr',
    }

    registers = {
        'x0': (16, 8),
        'x1': (24, 8),
        'x2': (32, 8),
        'x3': (40, 8),
        'x4': (48, 8),
        'x5': (56, 8),
        'x6': (64, 8),
        'x7': (72, 8),
        'x8': (80, 8),
        'x9': (88, 8),
        'x10': (96, 8),
        'x11': (104, 8),
        'x12': (112, 8),
        'x13': (120, 8),
        'x14': (128, 8),
        'x15': (136, 8),
        'x16': (144, 8),
        'x17': (152, 8),
        'x18': (160, 8),
        'x19': (168, 8),
        'x20': (176, 8),
        'x21': (184, 8),
        'x22': (192, 8),
        'x23': (200, 8),
        'x24': (208, 8),
        'x25': (216, 8),
        'x26': (224, 8),
        'x27': (232, 8),
        'x28': (240, 8),
        'bp': (248, 8),
        'x29': (248, 8),
        'lr': (256, 8),
        'x30': (256, 8),
        'sp': (264, 8),
        'x31': (264, 8),
        'xsp': (264, 8),
        'ip': (272, 8),
        'pc': (272, 8),
        'cc_op': (280, 8),
        'cc_dep1': (288, 8),
        'cc_dep2': (296, 8),
        'cc_ndep': (304, 8),
        'tpidr_el0': (312, 8),
        'q0': (320, 16),
        'q1': (336, 16),
        'q2': (352, 16),
        'q3': (368, 16),
        'q4': (384, 16),
        'q5': (400, 16),
        'q6': (416, 16),
        'q7': (432, 16),
        'q8': (448, 16),
        'q9': (464, 16),
        'q10': (480, 16),
        'q11': (496, 16),
        'q12': (512, 16),
        'q13': (528, 16),
        'q14': (544, 16),
        'q15': (560, 16),
        'q16': (576, 16),
        'q17': (592, 16),
        'q18': (608, 16),
        'q19': (624, 16),
        'q20': (640, 16),
        'q21': (656, 16),
        'q22': (672, 16),
        'q23': (688, 16),
        'q24': (704, 16),
        'q25': (720, 16),
        'q26': (736, 16),
        'q27': (752, 16),
        'q28': (768, 16),
        'q29': (784, 16),
        'q30': (800, 16),
        'q31': (816, 16),
        'qcflag': (832, 16),
        'emnote': (848, 4),
        'cmstart': (856, 8),
        'cmlen': (864, 8),
        'nraddr': (872, 8),
        'ip_at_syscall': (880, 8),
        'fpcr': (888, 4),
    }

    argument_registers = {
        registers['x0'][0],
        registers['x1'][0],
        registers['x2'][0],
        registers['x3'][0],
        registers['x4'][0],
        registers['x5'][0],
        registers['x6'][0],
        registers['x7'][0]
    }

    got_section_name = '.got'
    ld_linux_name = 'ld-linux-aarch64.so.1'
    elf_tls = TLSArchInfo(1, 32, [], [0], [], 0, 0)

register_arch([r'.*arm64.*|.*aarch64*'], 64, 'any', ArchAArch64)
