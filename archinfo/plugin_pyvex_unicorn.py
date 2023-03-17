from typing import Dict, List, Tuple

from .types import RegisterOffset
from .plugin import ArchPlugin
from .arch import Arch
from .arch_amd64 import ArchAMD64
from .arch_x86 import ArchX86
from .archerror import ArchPluginUnavailable

try:
    import unicorn
    __import__('pyvex')
except ModuleNotFoundError:
    raise ArchPluginUnavailable("pyvex and unicorn")

class PyvexUnicornPlugin(ArchPlugin, patches=Arch):
    cpu_flag_register_offsets_and_bitmasks_map: Dict[RegisterOffset, Tuple[int, int]] = {}
    reg_blacklist: List[str] = []
    reg_blacklist_offsets: List[RegisterOffset] = []
    vex_to_unicorn_map: Dict[RegisterOffset, Tuple[int, int]] = {}

    @classmethod
    def _init_2(cls, arch: Arch):
        if arch.uc_regs is not None:
            # VEX register offset to unicorn register ID map
            arch.vex_to_unicorn_map = {}
            pc_reg_name = arch.get_register_by_name("pc")
            for reg_name, unicorn_reg_id in arch.uc_regs.items():
                if reg_name == pc_reg_name:
                    continue

                vex_reg = arch.get_register_by_name(reg_name)
                arch.vex_to_unicorn_map[vex_reg.vex_offset] = (unicorn_reg_id, vex_reg.size)


class PyvexUnicornAMD64(PyvexUnicornPlugin, patches=ArchAMD64):
    @classmethod
    def _init_2(cls, arch: Arch):
        # Register blacklist
        reg_blacklist = ("fs", "gs")
        for register in arch.register_list:
            if register.name in reg_blacklist:
                arch.reg_blacklist.append(register.name)
                arch.reg_blacklist_offsets.append(arch.register_files['pyvex'].name_to_offset[register.name])

        # CPU flag registers
        uc_flags_reg = unicorn.x86_const.UC_X86_REG_EFLAGS
        cpu_flag_registers = {"d": 1 << 10, "ac": 1 << 18, "id": 1 << 21}
        for reg, reg_bitmask in cpu_flag_registers.items():
            reg_offset = arch.get_register_offset(reg)
            arch.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_flags_reg, reg_bitmask)

        mxcsr_registers = {"sseround": 1 << 14 | 1 << 13}
        uc_mxcsr_reg = unicorn.x86_const.UC_X86_REG_MXCSR
        for reg, reg_bitmask in mxcsr_registers.items():
            reg_offset = arch.get_register_offset(reg)
            arch.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_mxcsr_reg, reg_bitmask)


class PyvexUnicornX86(PyvexUnicornPlugin, patches=ArchX86):
    @classmethod
    def _init_2(cls, arch: Arch):
        # Register blacklist
        reg_blacklist = ("cs", "ds", "es", "fs", "gs", "ss", "gdt", "ldt")
        for register in arch.register_list:
            if register.name in reg_blacklist:
                arch.reg_blacklist.append(register.name)
                arch.reg_blacklist_offsets.append(arch.register_files['pyvex'].name_to_offset[register.name])

        # CPU flag registers
        uc_flags_reg = unicorn.x86_const.UC_X86_REG_EFLAGS
        cpu_flag_registers = {"d": 1 << 10, "ac": 1 << 18, "id": 1 << 21}
        for reg, reg_bitmask in cpu_flag_registers.items():
            reg_offset = arch.get_register_offset(reg)
            arch.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_flags_reg, reg_bitmask)

        mxcsr_registers = {"sseround": 1 << 14 | 1 << 13}
        uc_mxcsr_reg = unicorn.x86_const.UC_X86_REG_MXCSR
        for reg, reg_bitmask in mxcsr_registers.items():
            reg_offset = arch.get_register_offset(reg)
            arch.cpu_flag_register_offsets_and_bitmasks_map[reg_offset] = (uc_mxcsr_reg, reg_bitmask)
