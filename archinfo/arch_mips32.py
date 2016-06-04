import capstone as _capstone

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch

# FIXME: Tell fish to fix whatever he was storing in info['current_function']
# TODO: Only persist t9 in PIC programs

class ArchMIPS32(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchMIPS32, self).__init__(endness)
        if endness == 'Iend_BE':

            self.function_prologs = {
                r"\x27\xbd\xff[\x00-\xff]"                                          # addiu $sp, xxx
                r"\x3c\x1c[\x00-\xff][\x00-\xff]\x9c\x27[\x00-\xff][\x00-\xff]"     # lui $gp, xxx; addiu $gp, $gp, xxxx
            }
            self.function_epilogs = {
                r"\x8f\xbf[\x00-\xff]{2}([\x00-\xff]{4}){0,4}\x03\xe0\x00\x08"      # lw ra, off(sp); ... ; jr ra
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
    ip_offset = 128
    sp_offset = 116
    bp_offset = 120
    ret_offset = 8
    syscall_num_offset = 8
    call_pushes_ret = False
    stack_change = -4
    sizeof = {'int': 32, 'long': 32, 'long long': 64}
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
        0: 'zero',
        4: 'at',
        8: 'v0',
        12: 'v1',
        16: 'a0',
        20: 'a1',
        24: 'a2',
        28: 'a3',
        32: 't0',
        36: 't1',
        40: 't2',
        44: 't3',
        48: 't4',
        52: 't5',
        56: 't6',
        60: 't7',
        64: 's0',
        68: 's1',
        72: 's2',
        76: 's3',
        80: 's4',
        84: 's5',
        88: 's6',
        92: 's7',
        96: 't8',
        100: 't9',
        104: 'k0',
        108: 'k1',
        112: 'gp',
        116: 'sp',
        120: 's8',
        124: 'ra',

        128: 'pc',

        132: 'hi',
        136: 'lo',

        144: 'f0',
        152: 'f1',
        160: 'f2',
        168: 'f3',
        176: 'f4',
        184: 'f5',
        192: 'f6',
        200: 'f7',
        208: 'f8',
        216: 'f9',
        224: 'f10',
        232: 'f11',
        240: 'f12',
        248: 'f13',
        256: 'f14',
        264: 'f15',
        272: 'f16',
        280: 'f17',
        288: 'f18',
        296: 'f19',
        304: 'f20',
        312: 'f21',
        320: 'f22',
        328: 'f23',
        336: 'f24',
        344: 'f25',
        352: 'f26',
        360: 'f27',
        368: 'f28',
        376: 'f29',
        384: 'f30',
        392: 'f31',
        400: 'fir',
        404: 'fccr',
        408: 'fexr',
        412: 'fenr',
        416: 'fcsr',
        420: 'ulr',
        424: 'emnote',
        428: 'cmstart',
        432: 'cmlen',
        436: 'nraddr',
        440: 'evc_failaddr',
        444: 'evc_counter',
        448: 'cond',
        452: 'dspcontrol',
        456: 'ac0',
        464: 'ac1',
        472: 'ac2',
        480: 'ac3'
    }

    registers = {
        'r0': (0, 4), 'zero': (0, 4),
        'r1': (4, 4), 'at': (4, 4),
        'r2': (8, 4), 'v0': (8, 4),
        'r3': (12, 4), 'v1': (12, 4),
        'r4': (16, 4), 'a0': (16, 4),
        'r5': (20, 4), 'a1': (20, 4),
        'r6': (24, 4), 'a2': (24, 4),
        'r7': (28, 4), 'a3': (28, 4),
        'r8': (32, 4), 't0': (32, 4),
        'r9': (36, 4), 't1': (36, 4),
        'r10': (40, 4), 't2': (40, 4),
        'r11': (44, 4), 't3': (44, 4),
        'r12': (48, 4), 't4': (48, 4),
        'r13': (52, 4), 't5': (52, 4),
        'r14': (56, 4), 't6': (56, 4),
        'r15': (60, 4), 't7': (60, 4),
        'r16': (64, 4), 's0': (64, 4),
        'r17': (68, 4), 's1': (68, 4),
        'r18': (72, 4), 's2': (72, 4),
        'r19': (76, 4), 's3': (76, 4),
        'r20': (80, 4), 's4': (80, 4),
        'r21': (84, 4), 's5': (84, 4),
        'r22': (88, 4), 's6': (88, 4),
        'r23': (92, 4), 's7': (92, 4),
        'r24': (96, 4), 't8': (96, 4),
        'r25': (100, 4), 't9': (100, 4),
        'r26': (104, 4), 'k0': (104, 4),
        'r27': (108, 4), 'k1': (108, 4),
        'r28': (112, 4), 'gp': (112, 4),

        'r29': (116, 4), 'sp': (116, 4),

        'r30': (120, 4), 's8': (120, 4), 'bp': (120, 4), 'fp': (120, 4),

        'r31': (124, 4), 'ra': (124, 4), 'lr': (124, 4),

        'pc': (128, 4),
        'ip': (128, 4),

        'hi': (132, 4),
        'lo': (136, 4),

        # these registers are allocated 64 bits by VEX but they are only 32-bit
        # it's a little sketchy tbh because some 32-bit mips arches DO in fact have a
        # 64-bit FPU but I have no idea how to deal with those
        'f0': (144, 4),
        'f1': (152, 4),
        'f2': (160, 4),
        'f3': (168, 4),
        'f4': (176, 4),
        'f5': (184, 4),
        'f6': (192, 4),
        'f7': (200, 4),
        'f8': (208, 4),
        'f9': (216, 4),
        'f10': (224, 4),
        'f11': (232, 4),
        'f12': (240, 4),
        'f13': (248, 4),
        'f14': (256, 4),
        'f15': (264, 4),
        'f16': (272, 4),
        'f17': (280, 4),
        'f18': (288, 4),
        'f19': (296, 4),
        'f20': (304, 4),
        'f21': (312, 4),
        'f22': (320, 4),
        'f23': (328, 4),
        'f24': (336, 4),
        'f25': (344, 4),
        'f26': (352, 4),
        'f27': (360, 4),
        'f28': (368, 4),
        'f29': (376, 4),
        'f30': (384, 4),
        'f31': (392, 4),
        'fir': (400, 4),
        'fccr': (404, 4),
        'fexr': (408, 4),
        'fenr': (412, 4),
        'fcsr': (416, 4),
        'ulr': (420, 4),
        'emnote': (424, 4),
        'cmstart': (428, 4),
        'cmlen': (432, 4),
        'nraddr': (436, 4),
        'evc_failaddr': (440, 4),
        'evc_counter': (444, 4),
        'cond': (448, 4),
        'dspcontrol': (452, 4),
        'ac0': (456, 8),
        'ac1': (464, 8),
        'ac2': (472, 8),
        'ac3': (480, 8)
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

    dynamic_tag_translation = {
        0x70000001: 'DT_MIPS_RLD_VERSION',
        0x70000005: 'DT_MIPS_FLAGS',
        0x70000006: 'DT_MIPS_BASE_ADDRESS',
        0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
        0x70000011: 'DT_MIPS_SYMTABNO',
        0x70000012: 'DT_MIPS_UNREFEXTNO',
        0x70000013: 'DT_MIPS_GOTSYM',
        0x70000016: 'DT_MIPS_RLD_MAP',
        0x70000032: 'DT_MIPS_PLTGOT'
    }
    got_section_name = '.got'
    ld_linux_name = 'ld.so.1'
