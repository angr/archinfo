import logging
from typing import Union

try:
    import pypcode
except ImportError:
    pypcode = None

from .arch import Arch, Endness, Register
from .tls import TLSArchInfo
from .archerror import ArchError


log = logging.getLogger("__name__")


class ArchPcode(Arch):
    """
    archinfo interface to pypcode architectures. Provides minimal mapping for
    architectural info like register file map, endianness, bit width, etc.
    """

    def __init__(self, language: Union["pypcode.ArchLanguage", str]):
        if pypcode is None:
            raise ArchError("pypcode not installed")

        if isinstance(language, str):
            language = self._get_language_by_id(language)

        self.name = language.id
        self.pcode_arch = language.id
        self.description = language.description
        self.bits = int(language.size)
        self.endness = {"little": Endness.LE, "big": Endness.BE}[language.endian]
        self.instruction_endness = self.endness
        self.sizeof = {"short": 16, "int": 32, "long": 64, "long long": 64}
        self.elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

        # Build registers list
        ctx = pypcode.Context(language)
        archinfo_regs = {rname.lower(): Register(rname.lower(), r.size, r.offset) for rname, r in ctx.registers.items()}

        # Get program counter register
        pc_offset = None
        pc_tag = language.pspec.find("programcounter")
        if pc_tag is not None:
            pc_reg = pc_tag.attrib.get("register", None)
            if pc_reg is not None:
                # FIXME: Assumes RAM space
                pc_offset = ctx.registers[pc_reg].offset
                aliases = {"pc", "ip"}
                aliases.discard(pc_reg.lower())
                for alias in aliases:
                    archinfo_regs.pop(alias, None)
                archinfo_regs[pc_reg.lower()].alias_names = tuple(aliases)

        if pc_offset is None:
            log.warning("Unknown program counter register offset?")
            pc_offset = 0x80000000

        # Get stack pointer register
        sp_offset = None
        if len(language.cspecs):

            def find_matching_cid(language, desired):
                for cid in language.cspecs:
                    if cid[0] == desired:
                        return cid
                return None

            cspec_id = (
                find_matching_cid(language, "default") or find_matching_cid(language, "gcc") or list(language.cspecs)[0]
            )
            cspec = language.cspecs[cspec_id]
            sp_tag = cspec.find("stackpointer")
            if sp_tag is not None:
                sp_reg = sp_tag.attrib.get("register", None)
                if sp_reg is not None:
                    # FIXME: Assumes RAM space
                    sp_offset = ctx.registers[sp_reg].offset
                    if sp_reg.lower() != "sp":
                        if "sp" in archinfo_regs:
                            log.warning("Unexpected SP conflict")
                            del archinfo_regs["sp"]
                        archinfo_regs[sp_reg.lower()].alias_names += ("sp",)

        if sp_offset is None:
            log.warning("Unknown stack pointer register offset?")
            sp_offset = 0x80000008

        self.instruction_alignment = 1
        self.ip_offset = pc_offset
        self.sp_offset = sp_offset
        self.bp_offset = sp_offset
        self.register_list = list(archinfo_regs.values())
        self.initial_sp = (0x8000 << (self.bits - 16)) - 1
        self.linux_name = ""  # FIXME
        self.triplet = ""  # FIXME

        super().__init__(endness=self.endness, instruction_endness=self.instruction_endness)

    @staticmethod
    def _get_language_by_id(lang_id) -> "pypcode.ArchLanguage":
        for arch in pypcode.Arch.enumerate():
            for lang in arch.languages:
                if lang.id == lang_id:
                    return lang
        raise ArchError("Language not found")
