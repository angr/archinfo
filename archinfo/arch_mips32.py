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

# FIXME: Tell fish to fix whatever he was storing in info['current_function']
# TODO: Only persist t9 in PIC programs

class ArchMIPS32(Arch):
    def __init__(self, endness=Endness.BE):
        super(ArchMIPS32, self).__init__(endness)
        if endness == Endness.BE:

            self.function_prologs = {
                r"\x27\xbd\xff[\x00-\xff]"                                          # addiu $sp, xxx
                r"\x3c\x1c[\x00-\xff][\x00-\xff]\x9c\x27[\x00-\xff][\x00-\xff]"     # lui $gp, xxx; addiu $gp, $gp, xxxx
            }
            self.function_epilogs = {
                br"\x8f\xbf[\x00-\xff]{2}([\x00-\xff]{4}){0,4}\x03\xe0\x00\x08"      # lw ra, off(sp); ... ; jr ra
            }
            self.qemu_name = 'mips'
            self.triplet = 'mips-linux-gnu'
            self.linux_name = 'mips'

    bits = 32
    vex_arch = "VexArchMIPS32"
    name = "MIPS32"
    ida_processor = 'mipsb'
    qemu_name = 'mipsel'
    linux_name = 'mipsel' # ???
    triplet = 'mipsel-linux-gnu'
    max_inst_bytes = 4
    ip_offset = 136
    sp_offset = 124
    bp_offset = 128
    ret_offset = 16
    lr_offset = 132
    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -4
    branch_delay_slot = True
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_MIPS
        cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_MIPS if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.mips_const if _unicorn else None
    uc_prefix = "UC_MIPS_" if _unicorn else None
    function_prologs = {
        r"[\x00-\xff]\xff\xbd\x27",                                         # addiu $sp, xxx
        r"[\x00-\xff][\x00-\xff]\x1c\x3c[\x00-\xff][\x00-\xff]\x9c\x27"     # lui $gp, xxx; addiu $gp, $gp, xxxx
    }
    function_epilogs = {
        r"[\x00-\xff]{2}\xbf\x8f([\x00-\xff]{4}){0,4}\x08\x00\xe0\x03"      # lw ra, off(sp); ... ; jr ra
    }

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
        8: 'zero',
        12: 'at',
        16: 'v0',
        20: 'v1',
        24: 'a0',
        28: 'a1',
        32: 'a2',
        36: 'a3',
        40: 't0',
        44: 't1',
        48: 't2',
        52: 't3',
        56: 't4',
        60: 't5',
        64: 't6',
        68: 't7',
        72: 's0',
        76: 's1',
        80: 's2',
        84: 's3',
        88: 's4',
        92: 's5',
        96: 's6',
        100: 's7',
        104: 't8',
        108: 't9',
        112: 'k0',
        116: 'k1',
        120: 'gp',
        124: 'sp',
        128: 's8',
        132: 'ra',
        136: 'pc',
        140: 'hi',
        144: 'lo',
        152: 'f0',
        160: 'f1',
        168: 'f2',
        176: 'f3',
        184: 'f4',
        192: 'f5',
        200: 'f6',
        208: 'f7',
        216: 'f8',
        224: 'f9',
        232: 'f10',
        240: 'f11',
        248: 'f12',
        256: 'f13',
        264: 'f14',
        272: 'f15',
        280: 'f16',
        288: 'f17',
        296: 'f18',
        304: 'f19',
        312: 'f20',
        320: 'f21',
        328: 'f22',
        336: 'f23',
        344: 'f24',
        352: 'f25',
        360: 'f26',
        368: 'f27',
        376: 'f28',
        384: 'f29',
        392: 'f30',
        400: 'f31',
        408: 'fir',
        412: 'fccr',
        416: 'fexr',
        420: 'fenr',
        424: 'fcsr',
        428: 'ulr',
        432: 'emnote',
        436: 'cmstart',
        440: 'cmlen',
        444: 'nraddr',
        448: 'cond',
        452: 'dspcontrol',
        456: 'ac0',
        464: 'ac1',
        472: 'ac2',
        480: 'ac3',
        492: 'ip_at_syscall',
    }

    registers = {
        'r0': (8, 4),
        'zero': (8, 4),
        'at': (12, 4),
        'r1': (12, 4),
        'r2': (16, 4),
        'v0': (16, 4),
        'r3': (20, 4),
        'v1': (20, 4),
        'a0': (24, 4),
        'r4': (24, 4),
        'a1': (28, 4),
        'r5': (28, 4),
        'a2': (32, 4),
        'r6': (32, 4),
        'a3': (36, 4),
        'r7': (36, 4),
        'r8': (40, 4),
        't0': (40, 4),
        'r9': (44, 4),
        't1': (44, 4),
        'r10': (48, 4),
        't2': (48, 4),
        'r11': (52, 4),
        't3': (52, 4),
        'r12': (56, 4),
        't4': (56, 4),
        'r13': (60, 4),
        't5': (60, 4),
        'r14': (64, 4),
        't6': (64, 4),
        'r15': (68, 4),
        't7': (68, 4),
        'r16': (72, 4),
        's0': (72, 4),
        'r17': (76, 4),
        's1': (76, 4),
        'r18': (80, 4),
        's2': (80, 4),
        'r19': (84, 4),
        's3': (84, 4),
        'r20': (88, 4),
        's4': (88, 4),
        'r21': (92, 4),
        's5': (92, 4),
        'r22': (96, 4),
        's6': (96, 4),
        'r23': (100, 4),
        's7': (100, 4),
        'r24': (104, 4),
        't8': (104, 4),
        'r25': (108, 4),
        't9': (108, 4),
        'k0': (112, 4),
        'r26': (112, 4),
        'k1': (116, 4),
        'r27': (116, 4),
        'gp': (120, 4),
        'r28': (120, 4),
        'r29': (124, 4),
        'sp': (124, 4),
        'bp': (128, 4),
        'fp': (128, 4),
        'r30': (128, 4),
        's8': (128, 4),
        'lr': (132, 4),
        'r31': (132, 4),
        'ra': (132, 4),
        'ip': (136, 4),
        'pc': (136, 4),
        'hi': (140, 4),
        'lo': (144, 4),
        'f0': (152, 4),
        'f1': (160, 4),
        'f2': (168, 4),
        'f3': (176, 4),
        'f4': (184, 4),
        'f5': (192, 4),
        'f6': (200, 4),
        'f7': (208, 4),
        'f8': (216, 4),
        'f9': (224, 4),
        'f10': (232, 4),
        'f11': (240, 4),
        'f12': (248, 4),
        'f13': (256, 4),
        'f14': (264, 4),
        'f15': (272, 4),
        'f16': (280, 4),
        'f17': (288, 4),
        'f18': (296, 4),
        'f19': (304, 4),
        'f20': (312, 4),
        'f21': (320, 4),
        'f22': (328, 4),
        'f23': (336, 4),
        'f24': (344, 4),
        'f25': (352, 4),
        'f26': (360, 4),
        'f27': (368, 4),
        'f28': (376, 4),
        'f29': (384, 4),
        'f30': (392, 4),
        'f31': (400, 4),
        'fir': (408, 4),
        'fccr': (412, 4),
        'fexr': (416, 4),
        'fenr': (420, 4),
        'fcsr': (424, 4),
        'ulr': (428, 4),
        'emnote': (432, 4),
        'cmstart': (436, 4),
        'cmlen': (440, 4),
        'nraddr': (444, 4),
        'cond': (448, 4),
        'dspcontrol': (452, 4),
        'ac0': (456, 8),
        'ac1': (464, 8),
        'ac2': (472, 8),
        'ac3': (480, 8),
        'ip_at_syscall': (492, 4),
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

    # see https://github.com/radare/radare/blob/master/src/include/elf/mips.h
    dynamic_tag_translation = {
        0x70000001: 'DT_MIPS_RLD_VERSION',
        0x70000002: 'DT_MIPS_TIME_STAMP',
        0x70000003: 'DT_MIPS_ICHECKSUM',
        0x70000004: 'DT_MIPS_IVERSION',
        0x70000005: 'DT_MIPS_FLAGS',
        0x70000006: 'DT_MIPS_BASE_ADDRESS',
        0x70000007: 'DT_MIPS_MSYM',
        0x70000008: 'DT_MIPS_CONFLICT',
        0x70000009: 'DT_MIPS_LIBLIST',
        0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
        0x7000000b: 'DT_MIPS_CONFLICTNO',
        0x70000010: 'DT_MIPS_LIBLISTNO',
        0x70000011: 'DT_MIPS_SYMTABNO',
        0x70000012: 'DT_MIPS_UNREFEXTNO',
        0x70000013: 'DT_MIPS_GOTSYM',
        0x70000014: 'DT_MIPS_HIPAGENO',
        0x70000016: 'DT_MIPS_RLD_MAP',
        0x70000017: 'DT_MIPS_DELTA_CLASS',
        0x70000018: 'DT_MIPS_DELTA_CLASS_NO',
        0x70000019: 'DT_MIPS_DELTA_INSTANCE',
        0x7000001a: 'DT_MIPS_DELTA_INSTANCE_NO',
        0x7000001b: 'DT_MIPS_DELTA_RELOC',
        0x7000001c: 'DT_MIPS_DELTA_RELOC_NO',
        0x7000001d: 'DT_MIPS_DELTA_SYM',
        0x7000001e: 'DT_MIPS_DELTA_SYM_NO',
        0x70000020: 'DT_MIPS_DELTA_CLASSSYM',
        0x70000021: 'DT_MIPS_DELTA_CLASSSYM_NO',
        0x70000022: 'DT_MIPS_CXX_FLAGS',
        0x70000023: 'DT_MIPS_PIXIE_INIT',
        0x70000024: 'DT_MIPS_SYMBOL_LIB',
        0x70000025: 'DT_MIPS_LOCALPAGE_GOTIDX',
        0x70000026: 'DT_MIPS_LOCAL_GOTIDX',
        0x70000027: 'DT_MIPS_HIDDEN_GOTIDX',
        0x70000028: 'DT_MIPS_PROTECTED_GOTIDX',
        0x70000029: 'DT_MIPS_OPTIONS',
        0x7000002a: 'DT_MIPS_INTERFACE',
        0x7000002b: 'DT_MIPS_DYNSTR_ALIGN',
        0x7000002c: 'DT_MIPS_INTERFACE_SIZE',
        0x7000002d: 'DT_MIPS_RLD_TEXT_RESOLVE_ADDR',
        0x7000002e: 'DT_MIPS_PERF_SUFFIX',
        0x7000002f: 'DT_MIPS_COMPACT_SIZE',
        0x70000030: 'DT_MIPS_GP_VALUE',
        0x70000031: 'DT_MIPS_AUX_DYNAMIC',
        0x70000032: 'DT_MIPS_PLTGOT'

    }
    got_section_name = '.got'
    ld_linux_name = 'ld.so.1'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0x7000, 0x8000)

register_arch([r'mipsel|mipsle'], 32, Endness.LE , ArchMIPS32)
register_arch([r'.*mips.*'], 32, 'any' , ArchMIPS32)
