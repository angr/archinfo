import logging
import xml.etree.ElementTree as ET
from typing import Union

from .arch import Arch, Endness, Register
from .archerror import ArchError
from .tls import TLSArchInfo
from .types import RegisterOffset

try:
    import pypcode

    _has_pypcode = True
except ImportError:
    _has_pypcode = False


log = logging.getLogger(__name__)


class ArchPcode(Arch):
    """
    archinfo interface to pypcode architectures. Provides minimal mapping for
    architectural info like register file map, endianness, bit width, etc.
    """

    def __init__(self, language: Union["pypcode.ArchLanguage", str]):
        if not _has_pypcode:
            raise ArchError("pypcode not installed")

        if isinstance(language, str):
            language = self._get_language_by_id(language)

        assert isinstance(language, pypcode.ArchLanguage)

        self.name = language.id
        self.pcode_id = language.id
        self.description = language.description
        self.bits = int(language.size)
        self.endness = {"little": Endness.LE, "big": Endness.BE}[language.endian]
        self.instruction_endness = self.endness
        cspec = self._select_cspec(language)
        self.sizeof = self._get_c_type_sizes(cspec)
        call_stack_shift = self._get_call_stack_shift(cspec)
        self.call_pushes_ret = call_stack_shift > 0
        self.call_sp_fix = -call_stack_shift
        self.elf_tls = TLSArchInfo(1, 8, [], [0], [], 0, 0)

        # Build registers list
        ctx = pypcode.Context(language)
        archinfo_regs = {rname.lower(): Register(rname.lower(), r.size, r.offset) for rname, r in ctx.registers.items()}

        # Get program counter register
        pc_offset = None
        pc_tag = language.pspec.find("programcounter") if language.pspec is not None else None
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

        sp_offset = None
        ret_offset = RegisterOffset(0)
        if cspec is not None:
            # Get stack pointer register
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

            # Get return offset
            proto_tags = cspec.find("default_proto")
            if proto_tags is not None and len(proto_tags) >= 1:
                proto_tag = proto_tags[0]
                output_tags = proto_tag.find("output")
                if output_tags is not None and len(output_tags) >= 1:
                    output_tag = output_tags[0]
                    output_register_tag = output_tag.find("register")
                    if output_register_tag is not None:
                        output_reg = output_register_tag.attrib["name"]
                        ret_offset = RegisterOffset(ctx.registers[output_reg].offset)

        if sp_offset is None:
            log.warning("Unknown stack pointer register offset?")
            sp_offset = 0x80000008

        self.instruction_alignment = 1
        self.ip_offset = RegisterOffset(pc_offset)
        self.sp_offset = RegisterOffset(sp_offset)
        self.bp_offset = RegisterOffset(sp_offset)
        self.ret_offset = RegisterOffset(ret_offset)
        self.register_list = list(archinfo_regs.values())
        sp_bits = self.bits
        if "sp" in archinfo_regs:
            sp_bits = archinfo_regs["sp"].size * 8
        self.initial_sp = (0x8000 << (sp_bits - 16)) - 1
        self.linux_name = ""  # FIXME
        self.triplet = ""  # FIXME

        # TODO: Replace the following hardcoded function prologues by data sourced from patterns.xml
        if "PowerPC:BE" in self.name:
            self.function_prologs = {
                # stwu  r1, xx(r1); mfspr rx, lr
                b"\x94\x21[\xc0-\xff][\x00\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0]"
                b"[\x7c-\x7f][\x08\x28\x48\x68\x88\xa8\xc8\xe8]\x02\xa6",
            }
        if self.name.startswith("Xtensa:LE"):
            self.function_prologs = {
                # entry  a1, N
                b"\x36[\x11\x21\x31\x41\x51\x61\x71\x81\x91\xa1\xb1\xc1\xd1\xe1\xf1]\x00",
            }

        if "sparc:" in self.name.lower() and self.bits == 32:
            self.branch_delay_slot = True

        super().__init__(endness=self.endness, instruction_endness=self.instruction_endness)

    @staticmethod
    def _select_cspec(language: "pypcode.ArchLanguage") -> ET.Element | None:
        cspecs = language.cspecs
        if not cspecs:
            return None

        for preferred_id in ("default", "gcc"):
            for (compiler_id, _), cspec in cspecs.items():
                if compiler_id == preferred_id:
                    return cspec
        return next(iter(cspecs.values()))

    def _get_c_type_sizes(self, cspec: ET.Element | None) -> dict[str, int]:
        sizes = (
            {"short": 16, "int": 32, "long": 64, "long long": 64}
            if self.bits == 64
            else {"short": 16, "int": 32, "long": 32, "long long": 64}
        )
        if cspec is None:
            return sizes

        data_organization = cspec.find("data_organization")
        if data_organization is None:
            return sizes

        size_tags = {
            "short": "short_size",
            "int": "integer_size",
            "long": "long_size",
            "long long": "long_long_size",
        }
        for c_type, tag in size_tags.items():
            size_element = data_organization.find(tag)
            if size_element is None or "value" not in size_element.attrib:
                continue
            try:
                size = int(size_element.attrib["value"], 0)
            except ValueError:
                log.warning("Invalid %s value in compiler specification for %s", tag, self.name)
                continue
            if size <= 0:
                log.warning("Non-positive %s value in compiler specification for %s", tag, self.name)
                continue
            sizes[c_type] = size * self.byte_width

        return sizes

    def _get_call_stack_shift(self, cspec: ET.Element | None) -> int:
        """Return the stack delta caused by a call from the compiler specification."""

        if cspec is None:
            return 0

        prototype = cspec.find("./default_proto/prototype")
        if prototype is None or "stackshift" not in prototype.attrib:
            return 0

        try:
            stack_shift = int(prototype.attrib["stackshift"], 0)
        except ValueError:
            log.warning("Invalid stackshift value in compiler specification for %s", self.name)
            return 0
        if stack_shift < 0:
            log.warning("Negative stackshift value in compiler specification for %s", self.name)
            return 0
        return stack_shift

    def pcode_arch(self) -> "ArchPcode":
        """
        Return the ArchPcode instance for this architecture.
        For ArchPcode, this returns itself.

        :return: This ArchPcode instance
        """
        return self

    @staticmethod
    def _get_language_by_id(lang_id) -> "pypcode.ArchLanguage":
        if not _has_pypcode:
            raise ArchError("pypcode not installed")
        for arch in pypcode.Arch.enumerate():
            for lang in arch.languages:
                if lang.id == lang_id:
                    return lang
        raise ArchError("Language not found")

    def disasm(self, bytestring, addr=0, thumb=False):
        if not isinstance(bytestring, bytes):
            raise TypeError("bytestring must be bytes")
        if not bytestring:
            return ""

        ctx = pypcode.Context(self.name)
        # pypcode does not expose the context variables registered by the SLEIGH language.
        try:
            ctx.setVariableDefault("TMode", 1 if thumb else 0)
        except pypcode.LowlevelError:
            if thumb:
                log.warning("Specified thumb=True on architecture without a TMode context variable")

        instructions = ctx.disassemble(bytestring, addr, 0, len(bytestring), 0).instructions
        return "\n".join(f"{insn.addr.offset:#x}:\t{insn.mnem} {insn.body}" for insn in instructions)
