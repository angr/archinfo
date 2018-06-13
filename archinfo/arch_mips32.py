import logging

l = logging.getLogger("archinfo.arch_mips32")

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

from .arch import Arch, register_arch, Endness, Register
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
    if _keystone:
        ks_arch = _keystone.KS_ARCH_MIPS
        ks_mode = _keystone.KS_MODE_32 + _keystone.KS_MODE_LITTLE_ENDIAN
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
    register_list = [
        Register(name='zero', size=4, vex_offset=8, alias_names=('r0',)),
        Register(name='at', size=4, vex_offset=12, alias_names=('r1',),
                 general_purpose=True, argument=True),
        Register(name='v0', size=4, vex_offset=16, alias_names=('r2',),
                 general_purpose=True, linux_entry_value='ld_destructor'),
        Register(name='v1', size=4, vex_offset=20, alias_names=('r3',),
                 general_purpose=True),
        Register(name='a0', size=4, vex_offset=24, alias_names=('r4',), 
                 general_purpose=True, argument=True),
        Register(name='a1', size=4, vex_offset=28, alias_names=('r5',), 
                 general_purpose=True, argument=True),
        Register(name='a2', size=4, vex_offset=32, alias_names=('r6',), 
                 general_purpose=True, argument=True),
        Register(name='a3', size=4, vex_offset=36, alias_names=('r7',), 
                 general_purpose=True, argument=True),
        Register(name='t0', size=4, vex_offset=40, alias_names=('r8',), 
                 general_purpose=True),
        Register(name='t1', size=4, vex_offset=44, alias_names=('r9',), 
                 general_purpose=True),
        Register(name='t2', size=4, vex_offset=48, alias_names=('r10',), 
                 general_purpose=True),
        Register(name='t3', size=4, vex_offset=52, alias_names=('r11',), 
                 general_purpose=True),
        Register(name='t4', size=4, vex_offset=56, alias_names=('r12',), 
                 general_purpose=True),
        Register(name='t5', size=4, vex_offset=60, alias_names=('r13',), 
                 general_purpose=True),
        Register(name='t6', size=4, vex_offset=64, alias_names=('r14',), 
                 general_purpose=True),
        Register(name='t7', size=4, vex_offset=68, alias_names=('r15',), 
                 general_purpose=True),
        Register(name='s0', size=4, vex_offset=72, alias_names=('r16',), 
                 general_purpose=True),
        Register(name='s1', size=4, vex_offset=76, alias_names=('r17',), 
                 general_purpose=True),
        Register(name='s2', size=4, vex_offset=80, alias_names=('r18',), 
                 general_purpose=True),
        Register(name='s3', size=4, vex_offset=84, alias_names=('r19',), 
                 general_purpose=True),
        Register(name='s4', size=4, vex_offset=88, alias_names=('r20',), 
                 general_purpose=True),
        Register(name='s5', size=4, vex_offset=92, alias_names=('r21',), 
                 general_purpose=True),
        Register(name='s6', size=4, vex_offset=96, alias_names=('r22',), 
                 general_purpose=True),
        Register(name='s7', size=4, vex_offset=100, alias_names=('r23',), 
                 general_purpose=True),
        Register(name='t8', size=4, vex_offset=104, alias_names=('r24',), 
                 general_purpose=True),
        Register(name='t9', size=4, vex_offset=108, alias_names=('r25',), 
                 general_purpose=True, persistent=True),
        Register(name='k0', size=4, vex_offset=112, alias_names=('r26',), 
                 general_purpose=True),
        Register(name='k1', size=4, vex_offset=116, alias_names=('r27',), 
                 general_purpose=True),
        Register(name='gp', size=4, vex_offset=120, alias_names=('r28',), 
                 persistent=True),
        Register(name='sp', size=4, vex_offset=124, alias_names=('r29',), 
                 default_value=(Arch.initial_sp, True, 'global')),
        Register(name='s8', size=4, vex_offset=128, alias_names=('r30', 'fp', 'bp'), 
                 general_purpose=True),
        Register(name='ra', size=4, vex_offset=132, alias_names=('r31', 'lr'), 
                 general_purpose=True, persistent=True, linux_entry_value=0),
        Register(name='pc', size=4, vex_offset=136, alias_names=('ip',)), 
        Register(name='hi', size=4, vex_offset=140, general_purpose=True),
        Register(name='lo', size=4, vex_offset=144, general_purpose=True),
        Register(name='f0', size=8, vex_offset=152, floating_point=True),
        Register(name='f1', size=8, vex_offset=160, floating_point=True),
        Register(name='f2', size=8, vex_offset=168, floating_point=True),
        Register(name='f3', size=8, vex_offset=176, floating_point=True),
        Register(name='f4', size=8, vex_offset=184, floating_point=True),
        Register(name='f5', size=8, vex_offset=192, floating_point=True),
        Register(name='f6', size=8, vex_offset=200, floating_point=True),
        Register(name='f7', size=8, vex_offset=208, floating_point=True),
        Register(name='f8', size=8, vex_offset=216, floating_point=True),
        Register(name='f9', size=8, vex_offset=224, floating_point=True),
        Register(name='f10', size=8, vex_offset=232, floating_point=True),
        Register(name='f11', size=8, vex_offset=240, floating_point=True),
        Register(name='f12', size=8, vex_offset=248, floating_point=True),
        Register(name='f13', size=8, vex_offset=256, floating_point=True),
        Register(name='f14', size=8, vex_offset=264, floating_point=True),
        Register(name='f15', size=8, vex_offset=272, floating_point=True),
        Register(name='f16', size=8, vex_offset=280, floating_point=True),
        Register(name='f17', size=8, vex_offset=288, floating_point=True),
        Register(name='f18', size=8, vex_offset=296, floating_point=True),
        Register(name='f19', size=8, vex_offset=304, floating_point=True),
        Register(name='f20', size=8, vex_offset=312, floating_point=True),
        Register(name='f21', size=8, vex_offset=320, floating_point=True),
        Register(name='f22', size=8, vex_offset=328, floating_point=True),
        Register(name='f23', size=8, vex_offset=336, floating_point=True),
        Register(name='f24', size=8, vex_offset=344, floating_point=True),
        Register(name='f25', size=8, vex_offset=352, floating_point=True),
        Register(name='f26', size=8, vex_offset=360, floating_point=True),
        Register(name='f27', size=8, vex_offset=368, floating_point=True),
        Register(name='f28', size=8, vex_offset=376, floating_point=True),
        Register(name='f29', size=8, vex_offset=384, floating_point=True),
        Register(name='f30', size=8, vex_offset=392, floating_point=True),
        Register(name='f31', size=8, vex_offset=400, floating_point=True),
        Register(name='fir', size=4, vex_offset=408, floating_point=True),
        Register(name='fccr', size=4, vex_offset=412, floating_point=True),
        Register(name='fexr', size=4, vex_offset=416, floating_point=True),
        Register(name='fenr', size=4, vex_offset=420, floating_point=True),
        Register(name='fcsr', size=4, vex_offset=424, floating_point=True),
        Register(name='ulr', size=4, vex_offset=428),
        Register(name='emnote', size=4, vex_offset=432),
        Register(name='cmstart', size=4, vex_offset=436),
        Register(name='cmlen', size=4, vex_offset=440),
        Register(name='nraddr', size=4, vex_offset=444),
        Register(name='cond', size=4, vex_offset=448),
        Register(name='dspcontrol', size=4, vex_offset=452),
        Register(name='ac0', size=8, vex_offset=456),
        Register(name='ac1', size=8, vex_offset=464),
        Register(name='ac2', size=8, vex_offset=472),
        Register(name='ac3', size=8, vex_offset=480),
        Register(name='cp0_status', size=4, vex_offset=488),
        Register(name='ip_at_syscall', size=4, vex_offset=402),
    ]

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
