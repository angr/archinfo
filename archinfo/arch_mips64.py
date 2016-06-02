import capstone as _capstone

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch

class ArchMIPS64(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchMIPS64, self).__init__(endness)
        if endness == 'Iend_BE':

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
    ip_offset = 256
    sp_offset = 232
    bp_offset = 240
    ret_offset = 16
    syscall_register_offset = 16
    call_pushes_ret = False
    stack_change = -8
    sizeof = {'int': 32, 'long': 64, 'long long': 64}
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

    ret_instruction = "\x08\x00\xE0\x03" + "\x25\x08\x20\x00"
    nop_instruction = "\x00\x00\x00\x00"
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
        0:   'zero',
        8:   'at',
        16:  'v0',
        24:  'v1',
        32:  'a0',
        40:  'a1',
        48:  'a2',
        56:  'a3',
        64:  't0',
        72:  't1',
        80:  't2',
        88:  't3',
        96:  't4',
        104: 't5',
        112: 't6',
        120: 't7',
        128: 's0',
        136: 's1',
        144: 's2',
        152: 's3',
        160: 's4',
        168: 's5',
        176: 's6',
        184: 's7',
        192: 't8',
        200: 't9',
        208: 'k0',
        216: 'k1',
        224: 'gp',
        232: 'sp',
        240: 's8',
        248: 'ra',
        256: 'ip',
        264: 'hi',
        272: 'lo',
        280: 'f0',
        288: 'f1',
        296: 'f2',
        304: 'f3',
        312: 'f4',
        320: 'f5',
        328: 'f6',
        336: 'f7',
        344: 'f8',
        352: 'f9',
        360: 'f10',
        368: 'f11',
        376: 'f12',
        384: 'f13',
        392: 'f14',
        400: 'f15',
        408: 'f16',
        416: 'f17',
        424: 'f18',
        432: 'f19',
        440: 'f20',
        448: 'f21',
        456: 'f22',
        464: 'f23',
        472: 'f24',
        480: 'f25',
        488: 'f26',
        496: 'f27',
        504: 'f28',
        512: 'f29',
        520: 'f30',
        528: 'f31',
        536: 'fir',
        540: 'fccr',
        544: 'fexr',
        548: 'fenr',
        552: 'fcsr',
        560: 'ulr',
        568: 'emnote',
        576: 'cmstart',
        584: 'cmlen',
        592: 'nraddr',
        600: 'evc_failaddr',
        608: 'evc_counter',
        612: 'cond'
    }

    registers = {
        'r0': (0, 8),    'zero': (0, 8),
        'r1': (8, 8),    'at': (4, 8),
        'r2': (16, 8),   'v0': (16, 8),
        'r3': (24, 8),   'v1': (24, 8),
        'r4': (32, 8),   'a0': (32, 8),
        'r5': (40, 8),   'a1': (40, 8),
        'r6': (48, 8),   'a2': (48, 8),
        'r7': (56, 8),   'a3': (56, 8),
        'r8': (64, 8),   't0': (64, 8),
        'r9': (72, 8),   't1': (72, 8),
        'r10': (80, 8),  't2': (80, 8),
        'r11': (88, 8),  't3': (88, 8),
        'r12': (96, 8),  't4': (96, 8),
        'r13': (104, 8), 't5': (104, 8),
        'r14': (112, 8), 't6': (112, 8),
        'r15': (120, 8), 't7': (120, 8),
        'r16': (128, 8), 's0': (128, 8),
        'r17': (136, 8), 's1': (136, 8),
        'r18': (144, 8), 's2': (144, 8),
        'r19': (152, 8), 's3': (152, 8),
        'r20': (160, 8), 's4': (160, 8),
        'r21': (168, 8), 's5': (168, 8),
        'r22': (176, 8), 's6': (176, 8),
        'r23': (184, 8), 's7': (184, 8),
        'r24': (192, 8), 't8': (192, 8),
        'r25': (200, 8), 't9': (200, 8),
        'r26': (208, 8), 'k0': (208, 8),
        'r27': (216, 8), 'k1': (216, 8),
        'r28': (224, 8), 'gp': (224, 8),
        'r29': (232, 8), 'sp': (232, 8),
        'r30': (240, 8), 's8': (240, 8), 'bp': (240, 8), 'fp': (240, 8),
        'r31': (248, 8), 'ra': (248, 8), 'lr': (248, 8),
        'pc': (256, 8),  'ip': (256, 8),
        'hi': (264, 8),
        'lo': (272, 8),
        'f0': (280, 8),
        'f1': (288, 8),
        'f2': (296, 8),
        'f3': (304, 8),
        'f4': (312, 8),
        'f5': (320, 8),
        'f6': (328, 8),
        'f7': (336, 8),
        'f8': (344, 8),
        'f9': (352, 8),
        'f10': (360, 8),
        'f11': (368, 8),
        'f12': (376, 8),
        'f13': (384, 8),
        'f14': (392, 8),
        'f15': (400, 8),
        'f16': (408, 8),
        'f17': (416, 8),
        'f18': (424, 8),
        'f19': (432, 8),
        'f20': (440, 8),
        'f21': (448, 8),
        'f22': (456, 8),
        'f23': (464, 8),
        'f24': (472, 8),
        'f25': (480, 8),
        'f26': (488, 8),
        'f27': (496, 8),
        'f28': (504, 8),
        'f29': (512, 8),
        'f30': (520, 8),
        'f31': (528, 8),
        'fir': (536, 4),
        'fccr': (540, 4),
        'fexr': (544, 4),
        'fenr': (548, 4),
        'fcsr': (552, 4),
        'ulr': (560, 8),
        'emnote': (568, 4),
        'cmstart': (576, 8),
        'cmlen': (584, 8),
        'nraddr': (592, 8),
        'evc_failaddr': (600, 8),
        'evc_counter': (608, 4),
        'cond': (612, 4)
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
