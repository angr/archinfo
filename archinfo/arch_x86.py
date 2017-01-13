try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch
from .tls import TLSArchInfo
from .archerror import ArchError

class ArchX86(Arch):
    def __init__(self, endness='Iend_LE'):
        if endness != 'Iend_LE':
            raise ArchError('Arch i386 must be little endian')
        super(ArchX86, self).__init__(endness)
        if self.vex_archinfo:
            self.vex_archinfo['x86_cr0'] = 0xFFFFFFFF

    @property
    def capstone(self):
        if self.cs_arch is None:
            raise ArchError("Arch %s does not support disassembly with capstone" % self.name)
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.syntax = _capstone.CS_OPT_SYNTAX_ATT if self._x86_syntax == 'at&t' else _capstone.CS_OPT_SYNTAX_INTEL
            self._cs.detail = True
        return self._cs

    @property
    def capstone_x86_syntax(self):
        """
        Get the current syntax capstone uses for x86. It can be 'intel' or 'at&t'

        :return: Capstone's current x86 syntax
        :rtype: str
        """

        return self._x86_syntax

    @capstone_x86_syntax.setter
    def capstone_x86_syntax(self, new_syntax):
        """
        Set the syntax that capstone outputs for x86.
        """

        if new_syntax not in ('intel', 'at&t'):
            raise ArchError('Unsupported Capstone x86 syntax. It must be either "intel" or "at&t".')

        if new_syntax != self._x86_syntax:
            # clear the existing capstone instance
            self._cs = None
            self._x86_syntax = new_syntax

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
    vex_conditional_helpers = True
    syscall_num_offset = 8
    call_pushes_ret = True
    stack_change = -4
    memory_endness = "Iend_LE"
    register_endness = "Iend_LE"
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_X86
        cs_mode = _capstone.CS_MODE_32 + _capstone.CS_MODE_LITTLE_ENDIAN
    _x86_syntax = None # Set it to 'att' in order to use AT&T syntax for x86
    uc_arch = _unicorn.UC_ARCH_X86 if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_32 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.x86_const if _unicorn else None
    uc_prefix = "UC_X86_" if _unicorn else None
    function_prologs = [
        r"\x8b\xff\x55\x8b\xec", # mov edi, edi; push ebp; mov ebp, esp
        r"\x55\x8b\xec", # push ebp; mov ebp, esp
        r"\x55\x89\xe5",  # push ebp; mov ebp, esp
        r"\x55\x57\x56",  # push ebp; push edi; push esi
        # mov eax, 0x000000??; (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) sub esp
        r"\xb8[\x00-\xff]\x00\x00\x00[\x50\x51\x52\x53\x55\x56\x57]{0,7}\x8b[\x00-\xff]{2}",
        # (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) sub esp
        r"[\x50\x51\x52\x53\x55\x56\x57]{1,7}\x83\xec[\x00-\xff]{2,4}",
        # (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) mov xxx, xxx
        r"[\x50\x51\x52\x53\x55\x56\x57]{1,7}\x8b[\x00-\xff]{2}",
        r"(\x81|\x83)\xec",  # sub xxx %esp
    ]
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
        ( 'fpu_tags', 0, False, None),
        ( 'fs', 0, False, None),
        ( 'gs', 0, False, None)
    ]
    entry_register_values = {
        'eax': 0x1C,
        'edx': 'ld_destructor',
        'ebp': 0
    }
    default_symbolic_registers = [ 'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' ]
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
        72: 'mm0',
        80: 'mm1',
        88: 'mm2',
        96: 'mm3',
        104: 'mm4',
        112: 'mm5',
        120: 'mm6',
        128: 'mm7',
        136: 'fpu_tags',

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

        304: 'ldt', # THESE ARE REALLY TRICKY since their size depends on your host word size :(
        312: 'gdt',

        320: 'emnote',
        324: 'cmstart',
        328: 'cmlen',
        332: 'nraddr',
        336: 'sc_class',
        340: 'ip_at_syscall',
        344: 'padding1'
    }

    registers = {
        'eax': (8, 4), 'ax': (8, 2), 'al': (8, 1), 'ah': (9, 1),
        'ecx': (12, 4), 'cx': (12, 2), 'cl': (12, 1), 'ch': (13, 1),
        'edx': (16, 4), 'dx': (16, 2), 'dl': (16, 1), 'dh': (17, 1),
        'ebx': (20, 4), 'bx': (20, 2), 'bl': (20, 1), 'bh': (21, 1),

        'esp': (24, 4), 'sp': (24, 4),
        'ebp': (28, 4), 'bp': (28, 4),

        'esi': (32, 4), 'si': (32, 2), 'sil': (32, 1), 'sih': (33, 1),
        'edi': (36, 4), 'di': (36, 2), 'dil': (36, 1), 'dih': (37, 1),

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

        # fpu registers
        'fpu_regs': (72, 64),
        'mm0': (72, 8),
        'mm1': (80, 8),
        'mm2': (88, 8),
        'mm3': (96, 8),
        'mm4': (104, 8),
        'mm5': (112, 8),
        'mm6': (120, 8),
        'mm7': (128, 8),
        'fpu_tags': (136, 8),

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
        'gdt': (312, 8),

        'emnote': (320, 4),
        'cmstart': (324, 4),
        'cmlen': (328, 4),
        'nraddr': (332, 4),
        'sc_class': (336, 4),
        'ip_at_syscall':(340, 4),
        'padding1': (344, 4)
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
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)
