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

class ArchMIPS64(Arch):
    def __init__(self, endness=Endness.BE):
        super(ArchMIPS64, self).__init__(endness)
        if endness == Endness.BE:

            self.function_prologs = set((
                # TODO
            ))
            self.function_epilogs = set((
                # TODO
            ))
            self.triplet = 'mips64-linux-gnu'
            self.linux_name = 'mips64'
            self.ida_name = 'mips64b'

    bits = 64
    vex_arch = "VexArchMIPS64"
    name = "MIPS64"
    qemu_name = 'mips64el'
    ida_processor = 'mips64'
    linux_name = 'mips64el' # ???
    triplet = 'mips64el-linux-gnu'
    max_inst_bytes = 4
    ip_offset = 272
    sp_offset = 248
    bp_offset = 256
    ret_offset = 32
    lr_offset = 264
    syscall_register_offset = 16
    call_pushes_ret = False
    stack_change = -8
    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_MIPS
        cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_MIPS if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_64 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.mips_const if _unicorn else None
    uc_prefix = "UC_MIPS_" if _unicorn else None
    function_prologs = set((
        # TODO
    ))
    function_epilogs = set((
        # TODO
    ))

    ret_instruction = b"\x08\x00\xE0\x03" + b"\x25\x08\x20\x00"
    nop_instruction = b"\x00\x00\x00\x00"
    instruction_alignment = 4
    persistent_regs = ['gp', 'ra', 't9']

    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ),   # the stack
    ]
    entry_register_values = {
        'v0': 'ld_destructor',
        'ra': 0
    }

    default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                                   'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
                                   'r25', 'r26', 'r27', 'r28', 'sp', 'bp', 'lr', 'pc', 'hi', 'lo' ]

    register_names = {
        16: 'zero',
        24: 'at',
        32: 'v0',
        40: 'v1',
        48: 'a0',
        56: 'a1',
        64: 'a2',
        72: 'a3',
        80: 't0',
        88: 't1',
        96: 't2',
        104: 't3',
        112: 't4',
        120: 't5',
        128: 't6',
        136: 't7',
        144: 's0',
        152: 's1',
        160: 's2',
        168: 's3',
        176: 's4',
        184: 's5',
        192: 's6',
        200: 's7',
        208: 't8',
        216: 't9',
        224: 'k0',
        232: 'k1',
        240: 'gp',
        248: 'sp',
        256: 's8',
        264: 'ra',
        272: 'ip',
        280: 'hi',
        288: 'lo',
        296: 'f0',
        304: 'f1',
        312: 'f2',
        320: 'f3',
        328: 'f4',
        336: 'f5',
        344: 'f6',
        352: 'f7',
        360: 'f8',
        368: 'f9',
        376: 'f10',
        384: 'f11',
        392: 'f12',
        400: 'f13',
        408: 'f14',
        416: 'f15',
        424: 'f16',
        432: 'f17',
        440: 'f18',
        448: 'f19',
        456: 'f20',
        464: 'f21',
        472: 'f22',
        480: 'f23',
        488: 'f24',
        496: 'f25',
        504: 'f26',
        512: 'f27',
        520: 'f28',
        528: 'f29',
        536: 'f30',
        544: 'f31',
        552: 'fir',
        556: 'fccr',
        560: 'fexr',
        564: 'fenr',
        568: 'fcsr',
        576: 'ulr',
        584: 'emnote',
        588: 'cond',
        592: 'cmstart',
        600: 'cmlen',
        608: 'nraddr',
        616: 'ip_at_syscall',
    }

    registers = {
        'at': (16, 8),
        'r0': (16, 8),
        'zero': (16, 8),
        'r1': (24, 8),
        'r2': (32, 8),
        'v0': (32, 8),
        'r3': (40, 8),
        'v1': (40, 8),
        'a0': (48, 8),
        'r4': (48, 8),
        'a1': (56, 8),
        'r5': (56, 8),
        'a2': (64, 8),
        'r6': (64, 8),
        'a3': (72, 8),
        'r7': (72, 8),
        'r8': (80, 8),
        't0': (80, 8),
        'r9': (88, 8),
        't1': (88, 8),
        'r10': (96, 8),
        't2': (96, 8),
        'r11': (104, 8),
        't3': (104, 8),
        'r12': (112, 8),
        't4': (112, 8),
        'r13': (120, 8),
        't5': (120, 8),
        'r14': (128, 8),
        't6': (128, 8),
        'r15': (136, 8),
        't7': (136, 8),
        'r16': (144, 8),
        's0': (144, 8),
        'r17': (152, 8),
        's1': (152, 8),
        'r18': (160, 8),
        's2': (160, 8),
        'r19': (168, 8),
        's3': (168, 8),
        'r20': (176, 8),
        's4': (176, 8),
        'r21': (184, 8),
        's5': (184, 8),
        'r22': (192, 8),
        's6': (192, 8),
        'r23': (200, 8),
        's7': (200, 8),
        'r24': (208, 8),
        't8': (208, 8),
        'r25': (216, 8),
        't9': (216, 8),
        'k0': (224, 8),
        'r26': (224, 8),
        'k1': (232, 8),
        'r27': (232, 8),
        'gp': (240, 8),
        'r28': (240, 8),
        'r29': (248, 8),
        'sp': (248, 8),
        'bp': (256, 8),
        'fp': (256, 8),
        'r30': (256, 8),
        's8': (256, 8),
        'lr': (264, 8),
        'r31': (264, 8),
        'ra': (264, 8),
        'ip': (272, 8),
        'pc': (272, 8),
        'hi': (280, 8),
        'lo': (288, 8),
        'f0': (296, 8),
        'f1': (304, 8),
        'f2': (312, 8),
        'f3': (320, 8),
        'f4': (328, 8),
        'f5': (336, 8),
        'f6': (344, 8),
        'f7': (352, 8),
        'f8': (360, 8),
        'f9': (368, 8),
        'f10': (376, 8),
        'f11': (384, 8),
        'f12': (392, 8),
        'f13': (400, 8),
        'f14': (408, 8),
        'f15': (416, 8),
        'f16': (424, 8),
        'f17': (432, 8),
        'f18': (440, 8),
        'f19': (448, 8),
        'f20': (456, 8),
        'f21': (464, 8),
        'f22': (472, 8),
        'f23': (480, 8),
        'f24': (488, 8),
        'f25': (496, 8),
        'f26': (504, 8),
        'f27': (512, 8),
        'f28': (520, 8),
        'f29': (528, 8),
        'f30': (536, 8),
        'f31': (544, 8),
        'fir': (552, 4),
        'fccr': (556, 4),
        'fexr': (560, 4),
        'fenr': (564, 4),
        'fcsr': (568, 4),
        'ulr': (576, 8),
        'emnote': (584, 4),
        'cond': (588, 4),
        'cmstart': (592, 8),
        'cmlen': (600, 8),
        'nraddr': (608, 8),
        'ip_at_syscall': (616, 8),
    }

    argument_registers = {
        registers['v0'][0],
        registers['v1'][0],
        registers['a0'][0],
        registers['a2'][0],
        registers['a3'][0],
        registers['t0'][0],
        registers['t1'][0],
        registers['t2'][0],
        registers['t3'][0],
        registers['t4'][0],
        registers['t5'][0],
        registers['t6'][0],
        registers['t7'][0],
        registers['s0'][0],
        registers['s1'][0],
        registers['s2'][0],
        registers['s3'][0],
        registers['s4'][0],
        registers['s5'][0],
        registers['s6'][0],
        registers['t8'][0],
        registers['t9'][0]
    }

    # http://techpubs.sgi.com/library/manuals/4000/007-4658-001/pdf/007-4658-001.pdf
    dynamic_tag_translation = {
        0x70000001: 'DT_MIPS_RLD_VERSION',
        0x70000005: 'DT_MIPS_FLAGS',
        0x70000006: 'DT_MIPS_BASE_ADDRESS',
        0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
        0x70000011: 'DT_MIPS_SYMTABNO',
        0x70000012: 'DT_MIPS_UNREFEXTNO',
        0x70000013: 'DT_MIPS_GOTSYM',
        0x70000016: 'DT_MIPS_RLD_MAP'
    }
    got_section_name = '.got'
    ld_linux_name = 'ld.so.1'
    elf_tls = TLSArchInfo(1, 16, [], [0], [], 0x7000, 0x8000)

register_arch([r'.*mipsel.*|.*mips64el|.*mipsel64'], 64, Endness.LE, ArchMIPS64)
register_arch([r'.*mips64.*|.*mips.*'], 64, 'any', ArchMIPS64)
