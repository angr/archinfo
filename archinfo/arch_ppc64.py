import capstone as _capstone

#try:
#    import unicorn as _unicorn
#except ImportError:
#    _unicorn = None

from .arch import Arch

# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
# Normally r1 is used as stack pointer

class ArchPPC64(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchPPC64, self).__init__(endness)
        if endness == 'Iend_BE':
            self.function_prologs = {
                r"\x94\x21[\x00-\xff]{2}\x7c\x08\x02\xa6",                        # stwu r1, -off(r1); mflr r0
            }
            self.function_epilogs = {
                r"[\x00-\xff]{2}\x03\xa6([\x00-\xff]{4}){0,6}\x4e\x80\x00\x20"    # mtlr reg; ... ; blr
            }
            self.triplet = 'powerpc-linux-gnu'

    bits = 64
    vex_arch = "VexArchPPC64"
    name = "PPC64"
    qemu_name = 'ppc64'
    ida_processor = 'ppc64'
    triplet = 'powerpc64le-linux-gnu'
    linux_name = 'ppc750'
    max_inst_bytes = 4
    ip_offset = 1296
    sp_offset = 24
    bp_offset = 264
    ret_offset = 40
    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -8
    initial_sp = 0xffffffffff000000
    sizeof = {'int': 32, 'long': 64, 'long long': 64}
    cs_arch = _capstone.CS_ARCH_PPC
    cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    # unicorn not supported
    #uc_arch = _unicorn.UC_ARCH_PPC if _unicorn else None
    #uc_mode = (_unicorn.UC_MODE_64 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    ret_instruction = "\x20\x00\x80\x4e"
    nop_instruction = "\x00\x00\x00\x60"
    instruction_alignment = 4
    persistent_regs = [ 'r2' ]

    function_prologs = {
        r"[\x00-\xff]{2}\x21\x94\xa6\x02\x08\x7c",                        # stwu r1, -off(r1); mflr r0
    }
    function_epilogs = {
        r"\xa6\x03[\x00-\xff]{2}([\x00-\xff]{4}){0,6}\x20\x00\x80\x4e"    # mtlr reg; ... ; blr
    }

    default_register_values = [
        ( 'sp', initial_sp, True, 'global' ) # the stack
    ]
    entry_register_values = {
        'r2': 'toc',
        'r3': 'argc',
        'r4': 'argv',
        'r5': 'envp',
        'r6': 'auxv',
        'r7': 'ld_destructor'
    }

    register_names = {
        16: 'r0',
        24: 'r1',
        32: 'r2',
        40: 'r3',
        48: 'r4',
        56: 'r5',
        64: 'r6',
        72: 'r7',
        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',
        136: 'r15',
        144: 'r16',
        152: 'r17',
        160: 'r18',
        168: 'r19',
        176: 'r20',
        184: 'r21',
        192: 'r22',
        200: 'r23',
        208: 'r24',
        216: 'r25',
        224: 'r26',
        232: 'r27',
        240: 'r28',
        248: 'r29',
        256: 'r30',
        264: 'r31',

        1296: 'pc',
        1302: 'lr'
    }

    registers = {
        'r0': (16, 8),
        'r1': (24, 8), 'sp': (24, 8),
        'r2': (32, 8), 'rtoc': (32, 8),
        'r3': (40, 8),
        'r4': (48, 8),
        'r5': (56, 8),
        'r6': (64, 8),
        'r7': (72, 8),
        'r8': (80, 8),
        'r9': (88, 8),
        'r10': (96, 8),
        'r11': (104, 8),
        'r12': (112, 8),
        'r13': (120, 8),
        'r14': (128, 8),
        'r15': (136, 8), 'bp': (136, 8),
        'r16': (144, 8),
        'r17': (152, 8),
        'r18': (160, 8),
        'r19': (168, 8),
        'r20': (176, 8),
        'r21': (184, 8),
        'r22': (192, 8),
        'r23': (200, 8),
        'r24': (208, 8),
        'r25': (216, 8),
        'r26': (224, 8),
        'r27': (232, 8),
        'r28': (240, 8),
        'r29': (248, 8),
        'r30': (256, 8),
        'r31': (260, 8),

        'ip': (1296, 8), 'pc': (1296, 8),
        'lr': (1304, 8)
    }

    argument_registers = {
        registers['r0'],
        registers['r2'],
        registers['r3'],
        registers['r4'],
        registers['r5'],
        registers['r6'],
        registers['r7'],
        registers['r8'],
        registers['r9'],
        registers['r10'],
        registers['r11'],
        registers['r12'],
        registers['r13'],
        registers['r14'],
        registers['r15'],
        registers['r16'],
        registers['r17'],
        registers['r18'],
        registers['r19'],
        registers['r20'],
        registers['r21'],
        registers['r22'],
        registers['r23'],
        registers['r24'],
        registers['r25'],
        registers['r26'],
        registers['r27'],
        registers['r28'],
        registers['r29'],
        registers['r30'],
        registers['r31'],
    }

    got_section_name = '.plt'
    ld_linux_name = 'ld64.so.1'
