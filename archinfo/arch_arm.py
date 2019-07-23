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

from .arch import Arch, register_arch, Endness, Register
from .tls import TLSArchInfo

# TODO: determine proper base register (if it exists)
# TODO: handle multiple return registers?
# TODO: which endianness should be default?

def is_arm_arch(a):
    return a.name.startswith('ARM') or a.name.startswith("AArch")

def get_real_address_if_arm(arch, addr):
    """
    Obtain the real address of an instruction. ARM architectures are supported.

    :param Arch arch:   The Arch object.
    :param int addr:    The instruction address.
    :return:            The real address of an instruction.
    :rtype:             int
    """

    return ((addr >> 1) << 1) if is_arm_arch(arch) else addr

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
                br"\xe1\xa0\xc0\x0c\xe5\x2d\xe0\x04"
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
            self._ks_thumb = _keystone.Ks(self.ks_arch, _keystone.KS_MODE_THUMB)
        return self._ks_thumb

    @property
    def unicorn_thumb(self):
        if _unicorn is None:
            l.warning("Unicorn is not installed!")
            return None
        return _unicorn.Uc(self.uc_arch, self.uc_mode + _unicorn.UC_MODE_THUMB)

    def m_addr(self, addr, *args, **kwargs):
        """
        Given the address of some code block, convert it to the address where this block
        is stored in memory. The memory address can also be referred to as the "real" address.

        For ARM-architecture, the "real" address is always even (has its lowest bit clear).

        :param addr:    The address to convert.
        :return:        The "real" address in memory.
        :rtype:         int
        """
        return addr & ~1

    # pylint: disable=keyword-arg-before-vararg, arguments-differ
    def x_addr(self, addr, thumb=None, *args, **kwargs):
        """
        Given the address of some code block, convert it to the value that should be assigned
        to the instruction pointer register in order to execute the code in that block.

        :param addr:    The address to convert.
        :param thumb:   Set this parameter to True if you want to convert the address into the THUMB form.
                        Set this parameter to False if you want to convert the address into the ARM form.
                        Set this parameter to None (default) if you want to keep the address as is.
        :return:        The "execution" address.
        :rtype:         int
        """
        if thumb is None:
            return addr
        elif not thumb:
            return addr & ~1
        else:  # thumb
            return addr | 1

    def is_thumb(self, addr):  # pylint:disable=unused-argument
        """
        Return True, if the address is the THUMB address. False otherwise.

        :param addr:    The address to check.
        :return:        Whether the given address is the THUMB address.
        """
        return bool(addr & 1)

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
        ks_mode = _keystone.KS_MODE_ARM + _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_thumb = None
    uc_arch = _unicorn.UC_ARCH_ARM if _unicorn else None
    uc_mode = _unicorn.UC_MODE_LITTLE_ENDIAN if _unicorn else None
    uc_const = _unicorn.arm_const if _unicorn else None
    uc_prefix = "UC_ARM_" if _unicorn else None
    #self.ret_instruction = b"\x0E\xF0\xA0\xE1" # this is mov pc, lr
    ret_instruction = b"\x1E\xFF\x2F\xE1" # this is bx lr
    nop_instruction = b"\x00\x00\x00\x00"
    function_prologs = {
        br"[\x00-\xff][\x00-\xff]\x2d\xe9",                # stmfd sp!, {xxxxx}
        br"\x04\xe0\x2d\xe5",                              # push {lr}
        br"\r\xc0\xa0\xe1[\x00-\xff][\x00-\xff]\x2d\xe9",  # mov r12, sp;  stmfd sp!, {xxxxx}
        br"\r\xc0\xa0\xe1\x04\xe0\x2d\xe5",                # mov r12, sp; push {lr}
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
        Register(name='cc_op', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_dep1', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_dep2', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_ndep', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='qflag32', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='geflag0', size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='geflag1', size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='geflag2', size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='geflag3', size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='emnote', size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cmstart', size=4, artificial=True, vector=True, default_value=(0, False, None), concrete=False),
        Register(name='cmlen', size=4, artificial=True, default_value=(0, False, None), concrete=False),
        Register(name='nraddr', size=4, artificial=True, default_value=(0, False, None), concrete=False),
        Register(name='ip_at_syscall', size=4, artificial=True, concrete=False),
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
        Register(name='fpscr', size=4, floating_point=True, artificial=True, concrete=False),
        Register(name='tpidruro', size=4, artificial=True, concrete=False),
        Register(name='itstate', size=4, artificial=True, default_value=(0, False, None), concrete=False),
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

class ArchARMCortexM(ArchARMEL):
    """
    This is an architecture description for ARM Cortex-M microcontroller-class CPUs.

    These CPUs have the following unusual / annoying distinctions from their relatives:
    - Explicitly only support the Thumb-2 instruction set.  Executing with the T-bit off causes the processor to fault
    instantly
    - Always little-endian
    - Coprocessors? Nope, none of that rubbish
    - Well-known standard memory map across all devices
    - Rarely use an MPU, even though this does exist on some devices
    - A built-in "NVIC" (Nested Vectored Interrupt Controller) as part of the standard.
    - Standardized "blob format" including the IVT, with initial SP and entry prepended
    - Usually don't run an OS (SimLinux? No thanks)
    - As part of the above, handle syscalls (SVC) instructions through an interrupt (now called PendSV)
    Uses its own fancy stack layout for this, which (UGH) varies by sub-sub-architecture
    - Some fancy instructions normally never seen in other uses of Thumb (CPSID, CPSIE, WFI, MRS.W, MSR.W)
    - New registers, namely:
    * FAULTMASK
    * PRIMASK
    * BASEPRI
    * CONTROL
    * SP, banked as PSP or MSP
    * PSR, now just one PSR, with a few meta-registers APSR, IPSR, and EPSR which take a chunk of that each
    
    """

    name = "ARMCortexM"
    triplet = 'arm-none-eabi'  # ARM's own CM compilers use this triplet

    # These are the standard THUMB prologs.  We leave these off for other ARMs due to their length
    # For CM, we assume the FPs are OK, as they are almost guaranteed to appear all over the place
    function_prologs = {}

    thumb_prologs = {
        br"[\x00-\xff]\xb5",  # push {xxx,lr}
        br"\x2d\xe9[\x00-\xff][\x00-\xff]"  # push.w {xxx, lr}
    }
    function_epilogs = {
        br"[\x00-\xff]\xbd"  # pop {xxx, pc}
        # TODO: POP.W
    }

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
        Register(name='cc_op', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_dep1', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_dep2', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='cc_ndep', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='qflag32', size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name='ip_at_syscall', size=4, artificial=True, concrete=False),
        # Cortex-M Has a different FPU from all other ARMs.
        Register(name='d0', size=8, subregisters=[('s0', 0, 2), ('s1', 2, 2)], floating_point=True),
        Register(name='d1', size=8, subregisters=[('s2', 0, 2), ('s3', 2, 2)], floating_point=True),
        Register(name='d2', size=8, subregisters=[('s4', 0, 2), ('s5', 2, 2)], floating_point=True),
        Register(name='d3', size=8, subregisters=[('s6', 0, 2), ('s7', 2, 2)], floating_point=True),
        Register(name='d4', size=8, subregisters=[('s8', 0, 2), ('s9', 2, 2)], floating_point=True),
        Register(name='d5', size=8, subregisters=[('s10', 0, 2), ('s11', 2, 2)], floating_point=True),
        Register(name='d6', size=8, subregisters=[('s12', 0, 2), ('s13', 2, 2)], floating_point=True),
        Register(name='d7', size=8, subregisters=[('s14', 0, 2), ('s15', 2, 2)], floating_point=True),
        Register(name='d8', size=8, subregisters=[('s16', 0, 2), ('s17', 2, 2)], floating_point=True),
        Register(name='d9', size=8, subregisters=[('s18', 0, 2), ('s19', 2, 2)], floating_point=True),
        Register(name='d10', size=8, subregisters=[('s20', 0, 2), ('s21', 2, 2)], floating_point=True),
        Register(name='d11', size=8, subregisters=[('s22', 0, 2), ('s23', 2, 2)], floating_point=True),
        Register(name='d12', size=8, subregisters=[('s24', 0, 2), ('s25', 2, 2)], floating_point=True),
        Register(name='d13', size=8, subregisters=[('s26', 0, 2), ('s27', 2, 2)], floating_point=True),
        Register(name='d14', size=8, subregisters=[('s28', 0, 2), ('s29', 2, 2)], floating_point=True),
        Register(name='d15', size=8, subregisters=[('s30', 0, 2), ('s31', 2, 2)], floating_point=True),
        # TODO: NOTE: This is technically part of the EPSR, not its own register
        Register(name='fpscr', size=4, floating_point=True),
        # TODO: NOTE: This is also part of EPSR
        Register(name='itstate', size=4, artificial=True, default_value=(0, False, None), concrete=False),
        # Whether exceptions are masked or not. (e.g., everything but NMI)
        Register(name='faultmask', size=4, default_value=(0, False, None)),
        # The one-byte priority, above which interrupts will not be handled if PRIMASK is 1.
        # Yes, you can implement an RTOS scheduler in hardware with this and the NVIC, you monster!
        Register(name='basepri', size=4, default_value=(0, False, None)),
        # Only the bottom bit of PRIMASK is relevant, even though the docs say its 32bit.
        # Configures whether interrupt priorities are respected or not.
        Register(name='primask', size=4, default_value=(0, False, None)),
        # NOTE: We specifically declare IEPSR here.  Not PSR, .... variants.for
        # VEX already handles the content of APSR, and half of EPSR (as ITSTATE) above.
        # We only keep here the data not computed via CCalls
        # The default is to have the T bit on.
        Register(name='iepsr', size=4, default_value=(0x01000000, False, None)),
        # CONTROL:
        # Bit 2: Whether the FPU is active or not
        # Bit 1: Whether we use MSP (0) or PSP (1)
        # Bit 0: Thread mode privilege level. 0 for privileged, 1 for unprivileged.
        Register(name='control', size=4, default_value=(0, False, None))
    ]

    # Special handling of CM mode in *stone
    if _capstone:
        cs_arch = _capstone.CS_ARCH_ARM
        cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN + _capstone.CS_MODE_THUMB + _capstone.CS_MODE_MCLASS
    _cs_thumb = None
    if _keystone:
        ks_arch = _keystone.KS_ARCH_ARM
        ks_mode = _keystone.KS_MODE_THUMB + _keystone.KS_MODE_LITTLE_ENDIAN
    _ks_thumb = None

    @property
    def capstone_thumb(self):
        return self.capstone

    @property
    def keystone_thumb(self):
        return self.keystone

    def __init__(self, *args, **kwargs):
        super(ArchARMCortexM, self).__init__(*args, **kwargs)

    # TODO: Make arm_spotter use these
    # TODO: Make SimOS use these.
    # TODO: Add.... the NVIC? to SimOS


register_arch([r'.*cortexm|.*cortex\-m.*|.*v7\-m.*'], 32, 'any', ArchARMCortexM)
register_arch([r'.*armhf.*'], 32, 'any', ArchARMHF)
register_arch([r'.*armeb|.*armbe'], 32, Endness.BE, ArchARM)
register_arch([r'.*armel|arm.*'], 32, Endness.LE, ArchARMEL)
register_arch([r'.*arm.*|.*thumb.*'], 32, 'any', ArchARM)
