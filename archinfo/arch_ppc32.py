import capstone as _capstone

#try:
#   import unicorn as _unicorn
#except ImportError:
#   _unicorn = None

from .arch import Arch

# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
# PowerPC doesn't have stack base pointer, so bp_offset is set to -1 below
# Normally r1 is used as stack pointer

class ArchPPC32(Arch):
    def __init__(self, endness="Iend_LE"):
        super(ArchPPC32, self).__init__(endness)
        if endness == 'Iend_BE':
            self.function_prologs = {
                # stwu r1, -off(r1); mflr r0
                r"\x94\x21[\x00-\xff]{2}\x7c\x08\x02\xa6"
            }
            self.function_epilogs = {
                # mtlr reg; ... ; blr
                r"[\x00-\xff]{2}\x03\xa6([\x00-\xff]{4}){0,6}\x4e\x80\x00\x20"
            }

    bits = 32
    vex_arch = "VexArchPPC32"
    name = "PPC32"
    qemu_name = 'ppc'
    ida_processor = 'ppc'
    linux_name = 'ppc750'   # ?
    triplet = 'powerpc-linux-gnu'
    max_inst_bytes = 4
    ip_offset = 1160
    sp_offset = 20
    bp_offset = 140
    # https://www.ibm.com/developerworks/community/forums/html/topic?id=77777777-0000-0000-0000-000013836863
    # claims that r15 is the base pointer but that is NOT what I see in practice
    ret_offset = 28
    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -4
    sizeof = {'int': 32, 'long': 32, 'long long': 64}
    cs_arch = _capstone.CS_ARCH_PPC
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    # unicorn not supported
    #uc_arch = _unicorn.UC_ARCH_PPC if _unicorn else None
    #uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    ret_instruction = "\x20\x00\x80\x4e"
    nop_instruction = "\x00\x00\x00\x60"
    instruction_alignment = 4

    function_prologs = {
        r"[\x00-\xff]{2}\x21\x94\xa6\x02\x08\x7c",     # stwu r1, -off(r1); mflr r0
    }
    function_epilogs = {
        r"\xa6\x03[\x00-\xff]{2}([\x00-\xff]{4}){0,6}\x20\x00\x80\x4e"    # mtlr reg; ... ; blr
    }

    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ) # the stack
    ]
    entry_register_values = {
        'r3': 'argc',
        'r4': 'argv',
        'r5': 'envp',
        'r6': 'auxv',
        'r7': 'ld_destructor'
    }

    default_symbolic_registers = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                                   'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
                                   'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31', 'sp', 'pc']

    register_names = {
        16: 'r0',
        20: 'r1',
        24: 'r2',
        28: 'r3',
        32: 'r4',
        36: 'r5',
        40: 'r6',
        44: 'r7',
        48: 'r8',
        52: 'r9',
        56: 'r10',
        60: 'r11',
        64: 'r12',
        68: 'r13',
        72: 'r14',
        76: 'r15',
        80: 'r16',
        84: 'r17',
        88: 'r18',
        92: 'r19',
        96: 'r20',
        100: 'r21',
        104: 'r22',
        108: 'r23',
        112: 'r24',
        116: 'r25',
        120: 'r26',
        124: 'r27',
        128: 'r28',
        132: 'r29',
        136: 'r30',
        140: 'r31',

        1168: 'pc',
        1172: 'lr'
    }

    registers = {
        'r0': (16, 4),
        'r1': (20, 4), 'sp': (20, 4),
        'r2': (24, 4),
        'r3': (28, 4),
        'r4': (32, 4),
        'r5': (36, 4),
        'r6': (40, 4),
        'r7': (44, 4),
        'r8': (48, 4),
        'r9': (52, 4),
        'r10': (56, 4),
        'r11': (60, 4),
        'r12': (64, 4),
        'r13': (68, 4),
        'r14': (72, 4),
        'r15': (76, 4), 'bp': (76, 4),
        'r16': (80, 4),
        'r17': (84, 4),
        'r18': (88, 4),
        'r19': (92, 4),
        'r20': (96, 4),
        'r21': (100, 4),
        'r22': (104, 4),
        'r23': (108, 4),
        'r24': (112, 4),
        'r25': (116, 4),
        'r26': (120, 4),
        'r27': (124, 4),
        'r28': (128, 4),
        'r29': (132, 4),
        'r30': (136, 4),
        'r31': (140, 4),

        'ip': (1168, 4),
        'pc': (1168, 4),
        'lr': (1172, 4)
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
    ld_linux_name = 'ld.so.1'
