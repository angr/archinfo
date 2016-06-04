import capstone as _capstone

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch
from .archerror import ArchError

class ArchX86(Arch):
    def __init__(self, endness='Iend_LE'):
        if endness != 'Iend_LE':
            raise ArchError('Arch i386 must be little endian')
        super(ArchX86, self).__init__(endness)
        if self.vex_archinfo:
            self.vex_archinfo['x86_cr0'] = 0xFFFFFFFF

    bits = 32
    vex_arch = "VexArchX86"
    name = "X86"
    qemu_name = 'i386'
    ida_processor = 'metapc'
    linux_name = 'i386'
    triplet = 'i386-linux-gnu'
    max_inst_bytes = 15
    call_sp_fix = -8
    ip_offset = 68
    sp_offset = 24
    bp_offset = 28
    ret_offset = 8
    syscall_num_offset = 8
    call_pushes_ret = True
    stack_change = -4
    memory_endness = "Iend_LE"
    register_endness = "Iend_LE"
    sizeof = {'int': 32, 'long': 32, 'long long': 64}
    cs_arch = _capstone.CS_ARCH_X86
    cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    uc_arch = _unicorn.UC_ARCH_X86 if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.x86_const if _unicorn else None
    uc_prefix = "UC_X86_" if _unicorn else None
    function_prologs = {
        r"\x55\x8b\xec", # push ebp; mov ebp, esp
        r"\x55\x89\xe5",  # push ebp; mov ebp, esp
    }
    function_epilogs = {
        r"\xc9\xc3", # leave; ret
        r"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3", # pop <reg>; ret
        r"[^\x48][\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3", #  add esp, <siz>; retq
    }
    ret_instruction = "\xc3"
    nop_instruction = "\x90"
    instruction_alignment = 1
    default_register_values = [
        ( 'esp', Arch.initial_sp, True, 'global' ), # the stack
        ( 'd', 1, False, None ),
        ( 'fpround', 0, False, None ),
        ( 'sseround', 0, False, None ),
        ( 'gdt', 0, False, None ),
        ( 'ldt', 0, False, None ),
        ( 'id', 1, False, None ),
        ( 'ac', 0, False, None ),
        ( 'ftop', 0, False, None ),
        ( 'fpu_tags', 0, False, None)
    ]
    entry_register_values = {
        'eax': 0x1C,
        'edx': 'ld_destructor',
        'ebp': 0
    }
    default_symbolic_registers = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip' ]
    register_names = {
        8: 'eax',
        12: 'ecx',
        16: 'edx',
        20: 'ebx',

        24: 'esp',

        28: 'ebp',
        32: 'esi',
        36: 'edi',

        # condition stuff
        40: 'cc_op',
        44: 'cc_dep1',
        48: 'cc_dep2',
        52: 'cc_ndep',

        # this determines which direction SSE instructions go
        56: 'd',

        # separately-stored bits of eflags
        60: 'id',
        64: 'ac',

        68: 'eip',

        # fpu registers
        72: 'st7',
        80: 'st6',
        88: 'st5',
        96: 'st4',
        104: 'st3',
        112: 'st2',
        120: 'st1',
        128: 'st0',

        # fpu tags
        136: 'fpu_t0',
        137: 'fpu_t1',
        138: 'fpu_t2',
        139: 'fpu_t3',
        140: 'fpu_t4',
        141: 'fpu_t5',
        142: 'fpu_t6',
        143: 'fpu_t7',

        # fpu settings
        144: 'fpround',
        148: 'fc3210',
        152: 'ftop',

        # sse
        156: 'sseround',
        160: 'xmm0',
        176: 'xmm1',
        192: 'xmm2',
        208: 'xmm3',
        224: 'xmm4',
        240: 'xmm5',
        256: 'xmm6',
        272: 'xmm7',

        288: 'cs',
        290: 'ds',
        292: 'es',
        294: 'fs',
        296: 'gs',
        298: 'ss',

        304: 'ldt',
        312: 'gdt'
    }

    registers = {
        'eax': (8, 4),
        'ecx': (12, 4),
        'edx': (16, 4),
        'ebx': (20, 4),

        'sp': (24, 4),
        'esp': (24, 4),

        'ebp': (28, 4), 'bp': (28, 4),
        'esi': (32, 4),
        'edi': (36, 4),

        # condition stuff
        'cc_op': (40, 4),
        'cc_dep1': (44, 4),
        'cc_dep2': (48, 4),
        'cc_ndep': (52, 4),

        # this determines which direction SSE instructions go
        'd': (56, 4),

        # separately-stored bits of eflags
        'id': (60, 4),
        'ac': (64, 4),

        'eip': (68, 4),
        'pc': (68, 4),
        'ip': (68, 4),

        # fpu registers and mmx aliases
        'fpu_regs': (72, 64),
        'st7': (72, 8),
        'st6': (80, 8),
        'st5': (88, 8),
        'st4': (96, 8),
        'st3': (104, 8),
        'st2': (112, 8),
        'st1': (120, 8),
        'st0': (128, 8),
        'mm0': (72, 8),
        'mm1': (80, 8),
        'mm2': (88, 8),
        'mm3': (96, 8),
        'mm4': (104, 8),
        'mm5': (112, 8),
        'mm6': (120, 8),
        'mm7': (128, 8),

        # fpu tags
        'fpu_tags': (136, 8),
        'fpu_t0': (136, 1),
        'fpu_t1': (137, 1),
        'fpu_t2': (138, 1),
        'fpu_t3': (139, 1),
        'fpu_t4': (140, 1),
        'fpu_t5': (141, 1),
        'fpu_t6': (142, 1),
        'fpu_t7': (143, 1),

        # fpu settings
        'fpround': (144, 4),
        'fc3210': (148, 4),
        'ftop': (152, 4),

        # sse
        'sseround': (156, 4),
        'xmm0': (160, 16),
        'xmm1': (176, 16),
        'xmm2': (192, 16),
        'xmm3': (208, 16),
        'xmm4': (224, 16),
        'xmm5': (240, 16),
        'xmm6': (256, 16),
        'xmm7': (272, 16),

        'cs': (288, 2),
        'ds': (290, 2),
        'es': (292, 2),
        'fs': (294, 2),
        'gs': (296, 2),
        'ss': (298, 2),
        'ldt': (304, 8),
        'gdt': (312, 8)
    }

    argument_registers = { registers['eax'][0],
                           registers['ecx'][0],
                           registers['edx'][0],
                           registers['ebx'][0],
                           registers['ebp'][0],
                           registers['esi'][0],
                           registers['edi'][0] }

    lib_paths = ['/lib32', '/usr/lib32']
    got_section_name = '.got.plt'
    ld_linux_name = 'ld-linux.so.2'
