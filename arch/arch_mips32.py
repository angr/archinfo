import capstone as _capstone

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
            self.triplet = 'mips-linux-gnu'
            self.linux_name = 'mips'

    bits = 32
    vex_arch = "VexArchMIPS32"
    name = "MIPS32"
    qemu_name = 'mips'
    ida_processor = 'mipsb'
    linux_name = 'mipsel' # ???
    triplet = 'mipsel-linux-gnu'
    max_inst_bytes = 4
    ip_offset = 128
    sp_offset = 116
    bp_offset = 120
    ret_offset = 8
    call_pushes_ret = False
    stack_change = -4
    cs_arch = _capstone.CS_ARCH_MIPS
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
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

    default_symbolic_registers = [ 'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24', 'r25', 'r26', 'r27', 'r28', 'sp', 'bp', 'lr', 'pc', 'hi', 'lo' ]

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

    reloc_b_a = [3]  # ..?

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
