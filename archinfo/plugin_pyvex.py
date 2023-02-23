from typing import Optional, Dict, Tuple
import copy
import pyvex

from .plugin import ArchPlugin, RegisterPlugin
from .arch import Register, Endness, Arch
from .register import RegisterOffset, RegisterName
from .arch_amd64 import ArchAMD64
from .arch_x86 import ArchX86
from .arch_arm import ArchARM, ArchARMHF
from .arch_aarch64 import ArchAArch64
from .arch_mips32 import ArchMIPS32
from .arch_mips64 import ArchMIPS64
from .arch_ppc32 import ArchPPC32
from .arch_ppc64 import ArchPPC64
from .arch_s390x import ArchS390X


class PyvexRegisterPlugin(RegisterPlugin):
    def __init__(
        self,
        name,
        vex_offset=None,
        vex_name=None,
    ):
        super().__init__(name)
        self.vex_offset = vex_offset
        self.vex_name = vex_name


class PyvexPlugin(ArchPlugin, patches=Arch):
    vex_arch = None
    vex_archinfo = None

    # whether VEX has ccall handlers for conditionals for this arch
    vex_conditional_helpers = False

    # is it safe to cache IRSBs?
    cache_irsb = True

    # vex-specific registers
    __patched_registers = [
        PyvexRegisterPlugin(""),
    ]

    # some hardcoded offsets
    syscall_num_offset: Optional[RegisterOffset] = None
    ret_offset: Optional[RegisterOffset] = None
    fp_ret_offset: Optional[RegisterOffset] = None

    # some fields that get automatically filled
    ip_offset: Optional[RegisterOffset] = None
    sp_offset: Optional[RegisterOffset] = None
    bp_offset: Optional[RegisterOffset] = None
    lr_offset: Optional[RegisterOffset] = None
    artificial_register_offsets = []
    registers = {}
    register_names = {}
    register_size_names = {}
    subregister_map = {}
    vex_cc_regs = []
    argument_registers = set()
    argument_register_positions = {}

    @classmethod
    def _init_1(cls, arch):
        if arch.vex_support:
            arch.vex_archinfo = pyvex.enums.default_vex_archinfo()
            if arch.instruction_endness == Endness.BE:
                arch.vex_archinfo["endness"] = pyvex.enums.vex_endness_from_string("VexEndnessBE")

        if arch.register_list:
            (_, _), max_offset = max(pyvex.vex_ffi.guest_offsets.items(), key=lambda x: x[1])
            max_offset += arch.bits
            # Register collections
            if isinstance(arch.vex_arch, str):
                va = arch.vex_arch[7:].lower()
                for r in arch.register_list:
                    if r.vex_offset is None:
                        for name in (r.vex_name, r.name) + r.alias_names:
                            try:
                                r.vex_offset = pyvex.vex_ffi.guest_offsets[(va, name)]
                            except KeyError:
                                r.vex_offset = max_offset
                                max_offset += r.size
                            else:
                                break

            arch.register_names = {r.vex_offset: r.name for r in arch.register_list}
            arch.registers = get_register_dict(arch)
            arch.argument_registers = {r.vex_offset for r in arch.register_list if r.argument}
            arch.concretize_unique_registers = {r.vex_offset for r in arch.register_list if r.concretize_unique}

            # Artificial registers offsets
            arch.artificial_registers_offsets = []
            for reg_name in arch.artificial_registers:
                reg = arch.get_register_by_name(reg_name)
                arch.artificial_registers_offsets.extend(range(reg.vex_offset, reg.vex_offset + reg.size))

            # Register offsets
            arch.ip_offset = arch.registers.get("ip", (None, None))[0]
            arch.sp_offset = arch.registers.get("sp", (None, None))[0]
            arch.bp_offset = arch.registers.get("bp", (None, None))[0]
            arch.lr_offset = arch.registers.get("lr", (None, None))[0]

        # generate register mapping (offset, size): name
        arch.register_size_names = {}
        for reg in arch.register_list:
            if reg.vex_offset is None:
                continue
            arch.register_size_names[(reg.vex_offset, reg.size)] = reg.name
            for name, off, sz in reg.subregisters:
                # special hacks for X86 and AMD64 - don't translate register names to bp, sp, etc.
                if arch.name in {"X86", "AMD64"} and name in {"bp", "sp", "ip"}:
                    continue
                arch.register_size_names[(reg.vex_offset + off, sz)] = name

        # allow mapping a sub-register to its base register
        arch.subregister_map = {}
        for reg in arch.register_list:
            if reg.vex_offset is None:
                continue
            base_reg = reg.vex_offset, reg.size
            arch.subregister_map[(reg.vex_offset, reg.size)] = base_reg
            arch.subregister_map[reg.vex_offset] = base_reg
            for name, off, sz in reg.subregisters:
                if arch.name in {"X86", "AMD64"} and name in {"bp", "sp", "ip"}:
                    continue
                subreg_offset = reg.vex_offset + off
                arch.subregister_map[(subreg_offset, sz)] = base_reg
                if subreg_offset not in arch.subregister_map:
                    arch.subregister_map[subreg_offset] = base_reg

        # VEX registers used in lieu of flags register
        arch.vex_cc_regs = []
        vex_cc_register_names = ["cc_op", "cc_dep1", "cc_dep2", "cc_ndep"]
        for reg_name in vex_cc_register_names:
            vex_flag_reg = arch.get_register_by_name(reg_name)
            if vex_flag_reg is not None:
                arch.vex_cc_regs.append(vex_flag_reg)

    @classmethod
    def _prep_getstate(cls, arch):
        if arch.vex_archinfo is not None:
            # clear hwcacheinfo-caches because it may contain cffi.CData
            arch.vex_archinfo["hwcache_info"]["caches"] = None

    @classmethod
    def _prep_copy(cls, arch):
        arch.vex_archinfo = copy.deepcopy(arch.vex_archinfo)

    def translate_register_name(self, offset, size=None):
        if size is not None:
            try:
                return self.register_size_names[(offset, size)]
            except KeyError:
                pass

        try:
            return self.register_names[offset]
        except KeyError:
            return str(offset)

    def get_base_register(self, offset, size=None):
        """
        Convert a register or sub-register to its base register's offset.

        :param int offset:  The offset of the register to look up for.
        :param int size:    Size of the register.
        :return:            Offset and size of the base register, or None if no base register is found.
        """

        if size is None:
            key = offset
        else:
            key = (offset, size)

        return self.subregister_map.get(key, None)

    def get_register_offset(self, name):
        try:
            return self.registers[name][0]
        except KeyError as e:
            raise ValueError("Register %s does not exist!" % name) from e

    def is_artificial_register(self, offset, size):
        r = self.get_base_register(offset, size)
        if r is None:
            return False
        r_offset, _ = r

        try:
            r_name = self.register_names[r_offset]
        except KeyError:
            return False

        return r_name in self.artificial_registers

    @property
    def vex_support(self):
        """
        Whether the architecture is supported by VEX or not.

        :return: True if this Arch is supported by VEX, False otherwise.
        :rtype:  bool
        """

        return self.vex_arch is not None


def get_register_dict(arch) -> Dict[RegisterName, Tuple[RegisterOffset, int]]:
    res = {}
    for r in arch.register_list:
        if r.vex_offset is None:
            continue
        res[r.name] = (r.vex_offset, r.size)
        for i in r.alias_names:
            res[i] = (r.vex_offset, r.size)
        for reg, offset, size in r.subregisters:
            res[reg] = (r.vex_offset + offset, size)
    return res


class PyvexAMD64(PyvexPlugin, patches=ArchAMD64):
    vex_arch = "VexArchAMD64"
    vex_conditional_helpers = True
    syscall_num_offset = 16
    ret_offset = 16

    __patched_registers = [
        PyvexRegisterPlugin("fs", vex_name="fs_const"),
        PyvexRegisterPlugin("gs", vex_name="gs_const"),
        PyvexRegisterPlugin("cs_seg", vex_name="cs"),
        PyvexRegisterPlugin("ds_seg", vex_name="ds"),
        PyvexRegisterPlugin("es_seg", vex_name="es"),
        PyvexRegisterPlugin("fs_seg", vex_name="fs"),
        PyvexRegisterPlugin("fs_seg", vex_name="gs"),
        PyvexRegisterPlugin("ss_seg", vex_name="ss"),
    ]

    __new_registers = [
        Register(name="cc_op", size=8, default_value=(0, False, None), concrete=False, artificial=True),
        Register(name="cc_dep1", size=8, concrete=False, artificial=True),
        Register(name="cc_dep2", size=8, concrete=False, artificial=True),
        Register(name="cc_ndep", size=8, concrete=False, artificial=True, linux_entry_value=0),
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=8, concrete=False, artificial=True),
    ]

    @classmethod
    def _init_2(cls, arch):
        arch.argument_register_positions = {
            arch.registers["rdi"][0]: 0,
            arch.registers["rsi"][0]: 1,
            arch.registers["rdx"][0]: 2,
            arch.registers["rcx"][0]: 3,  # Used for user calls
            arch.registers["r10"][0]: 3,  # Used for Linux kernel calls
            arch.registers["r8"][0]: 4,
            arch.registers["r9"][0]: 5,
            # fp registers
            arch.registers["xmm0"][0]: 0,
            arch.registers["xmm1"][0]: 1,
            arch.registers["xmm2"][0]: 2,
            arch.registers["xmm3"][0]: 3,
            arch.registers["xmm4"][0]: 4,
            arch.registers["xmm5"][0]: 5,
            arch.registers["xmm6"][0]: 6,
            arch.registers["xmm7"][0]: 7,
        }


class PyvexX86(PyvexPlugin, patches=ArchX86):
    vex_arch = "VexArchX86"
    vex_conditional_helpers = True
    syscall_num_offset = 8
    ret_offset = 8

    __new_registers = [
        Register(name="cc_op", size=4, default_value=(0, False, None), concrete=False, artificial=True),
        Register(name="cc_dep1", size=4, concrete=False, artificial=True),
        Register(name="cc_dep2", size=4, concrete=False, artificial=True),
        Register(name="cc_ndep", size=4, concrete=False, artificial=True),
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=4, concrete=False, artificial=True),
    ]

    @classmethod
    def _init_2(cls, arch):
        arch.vex_archinfo["x86_cr0"] = 0xFFFFFFFF


class PyvexARM(PyvexPlugin, patches=ArchARM):
    vex_arch = "VexArchARM"
    vex_conditional_helpers = True
    ret_offset = 8
    fp_ret_offset = 8
    syscall_num_offset = 36

    __patched_registers = [
        PyvexRegisterPlugin(name="r15", vex_name="r15t"),
    ]

    __new_registers = [
        Register(name="cc_op", size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="cc_dep1", size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="cc_dep2", size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="cc_ndep", size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="qflag32", size=4, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="geflag0", size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="geflag1", size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="geflag2", size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="geflag3", size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="emnote", size=4, vector=True, default_value=(0, False, None), artificial=True, concrete=False),
        Register(name="cmstart", size=4, artificial=True, vector=True, default_value=(0, False, None), concrete=False),
        Register(name="cmlen", size=4, artificial=True, default_value=(0, False, None), concrete=False),
        Register(name="nraddr", size=4, artificial=True, default_value=(0, False, None), concrete=False),
        Register(name="ip_at_syscall", size=4, artificial=True, concrete=False),
    ]


class PyvexARMHF(PyvexPlugin, patches=ArchARMHF):
    fp_ret_offset = 128  # s0


# ?????
# class PyvexARMCortexM(PyvexPlugin, patches=ArchARMCortexM):
#    __new_registers = [
#        Register(name="qflag32", size=4, default_value=(0, False, None), artificial=True, concrete=False),
#    ]


class PyvexAArch64(PyvexPlugin, patches=ArchAArch64):
    vex_arch = "VexArchARM64"
    vex_conditional_helpers = True
    ret_offset = 16
    syscall_num_offset = 80

    __new_registers = [
        Register(name="cc_op", size=8, artificial=True),
        Register(name="cc_dep1", size=8, artificial=True),
        Register(name="cc_dep2", size=8, artificial=True),
        Register(name="cc_ndep", size=8, artificial=True),
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=8, artificial=True),
    ]


class PyvexMIPS32(PyvexPlugin, patches=ArchMIPS32):
    vex_arch = "VexArchMIPS32"
    ret_offset = 16
    syscall_num_offset = 16

    __new_registers = [
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=4, artificial=True),
    ]


class PyvexMIPS64(PyvexPlugin, patches=ArchMIPS64):
    vex_arch = "VexArchMIPS64"
    ret_offset = 32
    syscall_register_offset = 16

    __new_registers = [
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=8, artificial=True),
    ]


class PyvexPPC32(PyvexPlugin, patches=ArchPPC32):
    vex_arch = "VexArchPPC32"
    ret_offset = 28
    syscall_num_offset = 16

    __new_registers = [
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=4, artificial=True),
    ]

    @classmethod
    def _init_2(cls, arch):
        arch.argument_register_positions = {
            arch.registers["r3"][0]: 0,
            arch.registers["r4"][0]: 1,
            arch.registers["r5"][0]: 2,
            arch.registers["r6"][0]: 3,
            arch.registers["r7"][0]: 4,
            arch.registers["r8"][0]: 5,
            arch.registers["r9"][0]: 6,
            arch.registers["r10"][0]: 7,
        }


class PyvexPPC64(PyvexPlugin, patches=ArchPPC64):
    vex_arch = "VexArchPPC64"
    ret_offset = 40
    syscall_num_offset = 16

    __new_registers = [
        Register(name="emnote", size=4, artificial=True),
        Register(name="ip_at_syscall", size=8, artificial=True),
    ]

    @classmethod
    def _init_2(cls, arch):
        arch.argument_register_positions = {
            arch.registers["r3"][0]: 0,
            arch.registers["r4"][0]: 1,
            arch.registers["r5"][0]: 2,
            arch.registers["r6"][0]: 3,
            arch.registers["r7"][0]: 4,
            arch.registers["r8"][0]: 5,
            arch.registers["r9"][0]: 6,
            arch.registers["r10"][0]: 7,
            # fp registers
            arch.registers["vsr1"][0]: 0,
            arch.registers["vsr2"][0]: 1,
            arch.registers["vsr3"][0]: 2,
            arch.registers["vsr4"][0]: 3,
            arch.registers["vsr5"][0]: 4,
            arch.registers["vsr6"][0]: 5,
            arch.registers["vsr7"][0]: 6,
            arch.registers["vsr8"][0]: 7,
            arch.registers["vsr9"][0]: 8,
            arch.registers["vsr10"][0]: 9,
            arch.registers["vsr11"][0]: 10,
            arch.registers["vsr12"][0]: 11,
            arch.registers["vsr13"][0]: 12,
            # vector registers
            arch.registers["vsr2"][0]: 0,
            arch.registers["vsr3"][0]: 1,
            arch.registers["vsr4"][0]: 2,
            arch.registers["vsr5"][0]: 3,
            arch.registers["vsr6"][0]: 4,
            arch.registers["vsr7"][0]: 5,
            arch.registers["vsr8"][0]: 6,
            arch.registers["vsr9"][0]: 7,
            arch.registers["vsr10"][0]: 8,
            arch.registers["vsr11"][0]: 9,
            arch.registers["vsr12"][0]: 10,
            arch.registers["vsr13"][0]: 11,
        }


class PyvexS390X(PyvexPlugin, patches=ArchS390X):
    vex_arch = "VexArchS390X"  # enum VexArch
    ret_offset = 584  # offsetof(VexGuestS390XState, guest_r2)
    syscall_num_offset = 576  # offsetof(VexGuestS390XState, guest_r1)

    __new_registers = [
        Register(name="ip_at_syscall", size=8, artificial=True),
        Register(name="emnote", size=4, artificial=True),
    ]

    @classmethod
    def _init_2(cls, arch):
        arch.argument_register_positions = {
            arch.registers["r2"][0]: 0,
            arch.registers["r3"][0]: 1,
            arch.registers["r4"][0]: 2,
            arch.registers["r5"][0]: 3,
            arch.registers["r6"][0]: 4,
            # fp registers
            arch.registers["f0"][0]: 0,
            arch.registers["f2"][0]: 1,
            arch.registers["f4"][0]: 2,
            arch.registers["f6"][0]: 3,
        }
