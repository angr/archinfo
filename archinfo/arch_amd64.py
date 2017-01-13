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

class ArchAMD64(Arch):
    def __init__(self, endness='Iend_LE'):
        if endness != 'Iend_LE':
            raise ArchError('Arch AMD64 must be little endian')
        super(ArchAMD64, self).__init__(endness)

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

    bits = 64
    vex_arch = "VexArchAMD64"
    vex_endness = "VexEndnessLE"
    name = "AMD64"
    qemu_name = 'x86_64'
    ida_processor = 'metapc'
    linux_name = 'x86_64'
    triplet = 'x86_64-linux-gnu'
    max_inst_bytes = 15
    ip_offset = 184
    sp_offset = 48
    bp_offset = 56
    ret_offset = 16
    vex_conditional_helpers = True
    syscall_num_offset = 16
    call_pushes_ret = True
    stack_change = -8
    initial_sp = 0x7ffffffffff0000
    call_sp_fix = -8
    memory_endness = "Iend_LE"
    register_endness = "Iend_LE"
    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_X86
        cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    _x86_syntax = None # Set it to 'att' in order to use AT&T syntax for x86
    uc_arch = _unicorn.UC_ARCH_X86 if _unicorn else None
    uc_mode = (_unicorn.UC_MODE_64 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    uc_const = _unicorn.x86_const if _unicorn else None
    uc_prefix = "UC_X86_" if _unicorn else None
    function_prologs = {
        r"\x55\x48\x89\xe5", # push rbp; mov rbp, rsp
        r"\x48[\x83,\x81]\xec[\x00-\xff]", # sub rsp, xxx
    }
    function_epilogs = {
        r"\xc9\xc3", # leaveq; retq
        r"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3", # pop <reg>; retq
        r"\x48[\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3", #  add rsp, <siz>; retq
    }
    ret_instruction = "\xc3"
    nop_instruction = "\x90"
    instruction_alignment = 1
    default_register_values = [
        ( 'd', 1, False, None ),
        ( 'rsp', initial_sp, True, 'global' ),
        ( 'fs', 0x9000000000000000, True, 'global'),
        ( 'sseround', 0, False, None ),
        ( 'fpround', 0, False, None ),
        ( 'ftop', 0, False, None ),
        ( 'fpu_tags', 0, False, None ),
    ]
    entry_register_values = {
        'rax': 0x1c,
        'rdx': 'ld_destructor'
    }

    default_symbolic_registers = [ 'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11',
                                   'r12', 'r13', 'r14', 'r15', 'rip' ]

    register_names = {
        0: 'host_evc_failaddr',
        8: 'host_evc_counter',
        12: 'pad0',
        16: 'rax',
        24: 'rcx',
        32: 'rdx',
        40: 'rbx',
        48: 'rsp',
        56: 'rbp',
        64: 'rsi',
        72: 'rdi',
        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',
        136: 'r15',
        144: 'cc_op',
        152: 'cc_dep1',
        160: 'cc_dep2',
        168: 'cc_ndep',
        176: 'dflag',
        184: 'rip',
        192: 'acflag',
        200: 'idflag',
        208: 'fs_const',
        216: 'sseround',
        224: 'ymm0',
        256: 'ymm1',
        288: 'ymm2',
        320: 'ymm3',
        352: 'ymm4',
        384: 'ymm5',
        416: 'ymm6',
        448: 'ymm7',
        480: 'ymm8',
        512: 'ymm9',
        544: 'ymm10',
        576: 'ymm11',
        608: 'ymm12',
        640: 'ymm13',
        672: 'ymm14',
        704: 'ymm15',
        736: 'ymm16',
        768: 'ftop',
        772: 'pad1',
        776: 'mm0',
        784: 'mm1',
        792: 'mm2',
        800: 'mm3',
        808: 'mm4',
        816: 'mm5',
        824: 'mm6',
        832: 'mm7',
        840: 'fpu_tags',
        848: 'fpround',
        856: 'fc3210',
        864: 'emnote',
        868: 'pad2',
        872: 'cmstart',
        880: 'cmlen',
        888: 'nraddr',
        896: 'sc_class',
        904: 'gs_const',
        912: 'ip_at_syscall',
        920: 'pad3'
    }

    registers = {
        'host_evc_failaddr': (0, 8),
        'host_evc_counter': (8, 4),
        'pad0': (12, 4),

        'rax': (16, 8), 'eax': (16, 4), 'ax': (16, 2), 'al': (16, 1), 'ah': (17, 1),
        'rcx': (24, 8), 'ecx': (24, 4), 'cx': (24, 2), 'cl': (24, 1), 'ch': (25, 1),
        'rdx': (32, 8), 'edx': (32, 4), 'dx': (32, 2), 'dl': (32, 1), 'dh': (33, 1),
        'rbx': (40, 8), 'ebx': (40, 4), 'bx': (40, 2), 'bl': (40, 1), 'bh': (41, 1),
        'rsp': (48, 8), 'sp': (48, 8),
        'rbp': (56, 8), 'bp': (56, 8),
        'rsi': (64, 8), 'esi': (64, 4), 'si': (64, 2), 'sil': (64, 1), 'sih': (65, 1),
        'rdi': (72, 8), 'edi': (72, 4), 'di': (72, 2), 'dil': (72, 1), 'dih': (73, 1),
        'r8': (80, 8),
        'r9': (88, 8),
        'r10': (96, 8),
        'r11': (104, 8),
        'r12': (112, 8),
        'r13': (120, 8),
        'r14': (128, 8),
        'r15': (136, 8),

        'cc_op': (144, 8),
        'cc_dep1': (152, 8),
        'cc_dep2': (160, 8),
        'cc_ndep': (168, 8),

        'dflag': (176, 8), 'd': (176, 8),
        'rip': (184, 8), 'ip': (184, 8), 'pc': (184, 8),
        'acflag': (192, 8),
        'idflag': (200, 8),
        'fs_const': (208, 8), 'fs': (208, 8),
        'sseround': (216, 8),

        'ymm0': (224, 32),  'xmm0': (224, 32),
        'ymm1': (256, 32),  'xmm1': (256, 32),
        'ymm2': (288, 32),  'xmm2': (288, 32),
        'ymm3': (320, 32),  'xmm3': (320, 32),
        'ymm4': (352, 32),  'xmm4': (352, 32),
        'ymm5': (384, 32),  'xmm5': (384, 32),
        'ymm6': (416, 32),  'xmm6': (416, 32),
        'ymm7': (448, 32),  'xmm7': (448, 32),
        'ymm8': (480, 32),  'xmm8': (480, 32),
        'ymm9': (512, 32),  'xmm9': (512, 32),
        'ymm10': (544, 32), 'xmm10': (544, 32),
        'ymm11': (576, 32), 'xmm11': (576, 32),
        'ymm12': (608, 32), 'xmm12': (608, 32),
        'ymm13': (640, 32), 'xmm13': (640, 32),
        'ymm14': (672, 32), 'xmm14': (672, 32),
        'ymm15': (704, 32), 'xmm15': (704, 32),
        'ymm16': (736, 32), 'xmm16': (736, 32),

        'ftop': (768, 4),
        'pad1': (772, 4),

        'fpu_regs': (776, 64),
        'mm0': (776, 8),
        'mm1': (784, 8),
        'mm2': (792, 8),
        'mm3': (800, 8),
        'mm4': (808, 8),
        'mm5': (816, 8),
        'mm6': (824, 8),
        'mm7': (832, 8),
        'fpu_tags': (840, 8),

        'fpround': (848, 8),
        'fc3210': (856, 8),
        'emnote': (864, 4),
        'pad2': (868, 4),
        'cmstart': (872, 8),
        'cmlen': (880, 8),
        'nraddr': (888, 8),
        'sc_class': (896, 8),
        'gs_const': (904, 8), 'gs': (904, 8),
        'ip_at_syscall': (912, 8),
        'pad3': (920, 8)
    }

    argument_registers = {
        registers['rax'][0],
        registers['rcx'][0],
        registers['rdx'][0],
        registers['rbx'][0],
        registers['rsi'][0],
        registers['rdi'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0],
        registers['r11'][0],
        registers['r12'][0],
        registers['r13'][0],
        registers['r14'][0],
        registers['r15'][0],
    }

    symbol_type_translation = {
        10: 'STT_GNU_IFUNC',
        'STT_LOOS': 'STT_GNU_IFUNC'
    }
    got_section_name = '.got.plt'
    ld_linux_name = 'ld-linux-x86-64.so.2'
    elf_tls = TLSArchInfo(2, 704, [16], [8], [0], 0, 0)
