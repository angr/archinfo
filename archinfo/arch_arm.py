import logging

l = logging.getLogger("archinfo.arch_arm")

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

from .arch import Arch, register_arch, Endness, ArchError, Register
from .tls import TLSArchInfo

# TODO: determine proper base register (if it exists)
# TODO: handle multiple return registers?
# TODO: which endianness should be default?

class ArchARM(Arch):
    def __init__(self, endness=Endness.LE):

        instruction_endness = None
        if endness == Endness.LE:
            instruction_endness = Endness.LE

        super(ArchARM, self).__init__(endness,
                                      instruction_endness=instruction_endness
                                      )
        if endness == Endness.BE:
            self.function_prologs = {
                br"\xe9\x2d[\x00-\xff][\x00-\xff]",          # stmfd sp!, {xxxxx}
                br"\xe5\x2d\xe0\x04",                        # push {lr}
            }
            self.function_epilogs = {
                br"\xe8\xbd[\x00-\xff]{2}\xe1\x2f\xff\x1e"   # pop {xxx}; bx lr
                br"\xe4\x9d\xe0\x04\xe1\x2f\xff\x1e"         # pop {xxx}; bx lr
            }

    # ArchARM will match with any ARM, but ArchARMEL/ArchARMHF is a mismatch
    def __eq__(self, other):
        # pylint: disable=unidiomatic-typecheck
        if not isinstance(other, ArchARM):
            return False
        if self.memory_endness != other.memory_endness or self.bits != other.bits:
            return False
        if type(self) is type(other):
            return True
        if type(self) is ArchARM or type(other) is ArchARM:
            return True
        return False

    def __getstate__(self):
        self._cs = None
        self._cs_thumb = None
        self._ks = None
        self._ks_thumb = None
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)

    @property
    def capstone_thumb(self):
        if _capstone is None:
            l.warning("Capstone is not installed!")
            return None
        if self._cs_thumb is None:
            self._cs_thumb = _capstone.Cs(self.cs_arch, self.cs_mode + _capstone.CS_MODE_THUMB)
            self._cs_thumb.detail = True
        return self._cs_thumb

    @property
    def keystone_thumb(self):
        if _keystone is None:
            l.warning("Keystone is not installed!")
            return None
        if self._ks_thumb is None:
            mode = _keystone.KS_MODE_THUMB if thumb else _keystone.KS_MODE_ARM
            self._ks_thumb = _keystone.Ks(self.ks_arch, self.ks_mode + _keystone.KS_MODE_THUMB)
        return self._ks_thumb

    @property
    def unicorn_thumb(self):
        if _unicorn is None:
            l.warning("Unicorn is not installed!")
            return None
        return _unicorn.Uc(self.uc_arch, self.uc_mode + _unicorn.UC_MODE_THUMB)

    bits = 32
    vex_arch = "VexArchARM"
    name = "ARMEL"
    qemu_name = 'arm'
    ida_processor = 'armb'
    linux_name = 'arm'
    triplet = 'arm-linux-gnueabihf'
    max_inst_bytes = 4
    ret_offset = 8
    vex_conditional_helpers = True
    syscall_num_offset = 36
    call_pushes_ret = False
    stack_change = -4
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {'short': 16, 'int': 32, 'long': 32, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_ARM
        cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN
    _cs_thumb = None
    if _keystone:
        ks_arch = _keystone.KS_ARCH_ARM
        ks_mode = _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_thumb = None
    uc_arch = _unicorn.UC_ARCH_ARM if _unicorn else None
    uc_mode = _unicorn.UC_MODE_LITTLE_ENDIAN if _unicorn else None
    uc_const = _unicorn.arm_const if _unicorn else None
    uc_prefix = "UC_ARM_" if _unicorn else None
    #self.ret_instruction = b"\x0E\xF0\xA0\xE1" # this is mov pc, lr
    ret_instruction = b"\x1E\xFF\x2F\xE1" # this is bx lr
    nop_instruction = b"\x00\x00\x00\x00"
    function_prologs = {
        br"[\x00-\xff][\x00-\xff]\x2d\xe9",          # stmfd sp!, {xxxxx}
        br"\x04\xe0\x2d\xe5",                        # push {lr}
    }
    function_epilogs = {
        br"[\x00-\xff]{2}\xbd\xe8\x1e\xff\x2f\xe1"   # pop {xxx}; bx lr
        br"\x04\xe0\x9d\xe4\x1e\xff\x2f\xe1"         # pop {xxx}; bx lr
    }
    instruction_alignment = 2  # cuz there is also thumb mode
    register_list = [
        Register(name='r0', size=4, alias_names=('a1',),
                 general_purpose=True, argument=True, linux_entry_value='ld_destructor'),
        Register(name='r1', size=4, alias_names=('a2',),
                 general_purpose=True, argument=True),
        Register(name='r2', size=4, alias_names=('a3',),
                 general_purpose=True, argument=True),
        Register(name='r3', size=4, alias_names=('a4',),
                 general_purpose=True, argument=True),
        Register(name='r4', size=4, alias_names=('v1',),
                 general_purpose=True),
        Register(name='r5', size=4, alias_names=('v2',),
                 general_purpose=True),
        Register(name='r6', size=4, alias_names=('v3',),
                 general_purpose=True),
        Register(name='r7', size=4, alias_names=('v4',),
                 general_purpose=True),
        Register(name='r8', size=4, alias_names=('v5',),
                 general_purpose=True),
        Register(name='r9', size=4, alias_names=('v6', 'sb'),
                 general_purpose=True),
        Register(name='r10', size=4, alias_names=('v7', 'sl'),
                 general_purpose=True),
        Register(name='r11', size=4, alias_names=('v8', 'fp', 'bp'),
                 general_purpose=True),
        Register(name='r12', size=4, general_purpose=True),
        # r12 is sometimes known as "ip" (intraprocedural call scratch) but we can't have that...
        Register(name='sp', size=4, alias_names=('r13',),
                 general_purpose=True, default_value=(Arch.initial_sp, True, 'global')),
        Register(name='lr', size=4, alias_names=('r14',),
                 general_purpose=True, concretize_unique=True),
        Register(name='pc', size=4, vex_name='r15t', alias_names=('r15', 'ip')),
        Register(name='cc_op', size=4, default_value=(0, False, None)),
        Register(name='cc_dep1', size=4, default_value=(0, False, None)),
        Register(name='cc_dep2', size=4, default_value=(0, False, None)),
        Register(name='cc_ndep', size=4, default_value=(0, False, None)),
        Register(name='qflag32', size=4),
        Register(name='geflag0', size=4),
        Register(name='geflag1', size=4),
        Register(name='geflag2', size=4),
        Register(name='geflag3', size=4),
        Register(name='emnote', size=4),
        Register(name='cmstart', size=4),
        Register(name='cmlen', size=4),
        Register(name='nraddr', size=4),
        Register(name='ip_at_syscall', size=4),
        Register(name='d0', size=8, floating_point=True, vector=True),
        Register(name='d1', size=8, floating_point=True, vector=True),
        Register(name='d2', size=8, floating_point=True, vector=True),
        Register(name='d3', size=8, floating_point=True, vector=True),
        Register(name='d4', size=8, floating_point=True, vector=True),
        Register(name='d5', size=8, floating_point=True, vector=True),
        Register(name='d6', size=8, floating_point=True, vector=True),
        Register(name='d7', size=8, floating_point=True, vector=True),
        Register(name='d8', size=8, floating_point=True, vector=True),
        Register(name='d9', size=8, floating_point=True, vector=True),
        Register(name='d10', size=8, floating_point=True, vector=True),
        Register(name='d11', size=8, floating_point=True, vector=True),
        Register(name='d12', size=8, floating_point=True, vector=True),
        Register(name='d13', size=8, floating_point=True, vector=True),
        Register(name='d14', size=8, floating_point=True, vector=True),
        Register(name='d15', size=8, floating_point=True, vector=True),
        Register(name='d16', size=8, floating_point=True, vector=True),
        Register(name='d17', size=8, floating_point=True, vector=True),
        Register(name='d18', size=8, floating_point=True, vector=True),
        Register(name='d19', size=8, floating_point=True, vector=True),
        Register(name='d20', size=8, floating_point=True, vector=True),
        Register(name='d21', size=8, floating_point=True, vector=True),
        Register(name='d22', size=8, floating_point=True, vector=True),
        Register(name='d23', size=8, floating_point=True, vector=True),
        Register(name='d24', size=8, floating_point=True, vector=True),
        Register(name='d25', size=8, floating_point=True, vector=True),
        Register(name='d26', size=8, floating_point=True, vector=True),
        Register(name='d27', size=8, floating_point=True, vector=True),
        Register(name='d28', size=8, floating_point=True, vector=True),
        Register(name='d29', size=8, floating_point=True, vector=True),
        Register(name='d30', size=8, floating_point=True, vector=True),
        Register(name='d31', size=8, floating_point=True, vector=True),
        Register(name='fpscr', size=4, floating_point=True),
        Register(name='tpidruro', size=4),
        Register(name='itstate', size=4, default_value=(0, False, None)),
    ]

    got_section_name = '.got'
    ld_linux_name = 'ld-linux.so.3'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)
    #elf_tls = TLSArchInfo(1, 32, [], [0], [], 0, 0)
    # that line was lying in the original CLE code and I have no clue why it's different

class ArchARMHF(ArchARM):
    name = 'ARMHF'
    triplet = 'arm-linux-gnueabihf'
    ld_linux_name = 'ld-linux-armhf.so.3'

class ArchARMEL(ArchARM):
    name = 'ARMEL'
    triplet = 'arm-linux-gnueabi'
    ld_linux_name = 'ld-linux.so.3'
    elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

register_arch([r'.*armhf.*'], 32, 'any', ArchARMHF)
register_arch([r'.*armeb|.*armbe'], 32, Endness.BE, ArchARM)
register_arch([r'.*armel|arm.*'], 32, Endness.LE, ArchARMEL)
register_arch([r'.*arm.*|.*thumb.*'], 32, 'any', ArchARM)
