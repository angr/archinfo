import logging
from functools import cached_property
from collections import defaultdict
from typing import List
import struct as _struct
import platform as _platform
import re
from functools import partial
import copy

from .archerror import ArchError
from .tls import TLSArchInfo
from .register import Register, Endness

log = logging.getLogger("archinfo.arch")
log.addHandler(logging.NullHandler())

REGISTERED_ARCH_PLUGINS = defaultdict(list)
REGISTERED_REGISTER_PLUGINS = []


def _get_plugins(arch: "Arch"):
    for cls in reversed(type(arch).mro()):
        yield from REGISTERED_ARCH_PLUGINS[cls]


class Arch:
    """
    A collection of information about a given architecture. This class should be subclassed for each different
    architecture, and then that subclass should be registered with the ``register_arch`` method.

    Arches may be compared with == and !=.

    :ivar str name: The name of the arch
    :ivar int bits: The number of bits in a word
    :ivar str qemu_name: The name used by QEMU to identify this arch
    :ivar str ida_processor: The processor string used by IDA to identify this arch
    :ivar str triplet: The triplet used to identify a linux system on this arch
    :ivar int max_inst_bytes: The maximum number of bytes in a single instruction
    :ivar bool call_pushes_ret: Whether this arch's call instruction causes a stack push
    :ivar int stack_change: The change to the stack pointer caused by a push instruction
    :ivar str memory_endness: The endness of memory, as a VEX enum
    :ivar str register_endness: The endness of registers, as a VEX enum. Should usually be same as above
    :ivar str instruction_endness: The endness of instructions stored in memory.
        In other words, this controls whether instructions are stored endian-flipped compared to their description
        in the ISA manual, and should be flipped when lifted. Iend_BE means "don't flip"
        NOTE: Only used for non-libVEX lifters.
    :ivar dict sizeof: A mapping from C type to variable size in bits
    :ivar list function_prologs: A list of regular expressions matching the bytes for common function prologues
    :ivar list function_epilogs: A list of regular expressions matching the bytes for common function epilogues
    :ivar str ret_instruction: The bytes for a return instruction
    :ivar str nop_instruction: The bytes for a nop instruction
    :ivar int instruction_alignment: The instruction alignment requirement
    :ivar list default_register_values: A weird listing describing how registers should be initialized for purposes of
            sanity
    :ivar dict entry_register_values: A mapping from register name to a description of the value that should be in it
            at program entry on linux
    :ivar list default_symbolic_register: Honestly, who knows what this is supposed to do. Fill it with the names of
            the general purpose registers.
    :ivar list lib_paths: A listing of common locations where shared libraries for this architecture may be found
    :ivar str got_section_name: The name of the GOT section in ELFs
    :ivar str ld_linux_name: The name of the linux dynamic loader program
    :cvar int byte_width: the number of bits in a byte.
    :ivar TLSArchInfo elf_tls: A description of how thread-local storage works
    """

    byte_width = 8
    instruction_endness = "Iend_BE"
    elf_tls: TLSArchInfo = None

    def __init__(self, endness, instruction_endness=None):
        if endness not in (Endness.LE, Endness.BE, Endness.ME):
            raise ArchError("Must pass a valid endness: Endness.LE, Endness.BE, or Endness.ME")

        self.bytes = self.bits // self.byte_width
        self.register_list = list(self.register_list)

        if instruction_endness is not None:
            self.instruction_endness = instruction_endness

        register_plugins = defaultdict(dict)
        for plugin in _get_plugins(self):
            new_regs = vars(plugin).get(f"_{plugin.__name__}__new_registers", [])
            self.register_list.extend(new_regs)
            patch_regs = vars(plugin).get(f"_{plugin.__name__}__patched_registers", [])
            for reg in patch_regs:
                register_plugins[type(reg)][reg.name] = reg
        for ty, mapping in register_plugins.items():
            for reg in self.register_list:
                instance = mapping.get(reg.name, None) or ty(reg.name)
                for k, v in vars(instance).items():
                    if k == "name":
                        continue
                    if k in vars(reg):
                        raise TypeError(f"Register plugin property {k} would overwrite existing property")
                    setattr(reg, k, v)

        for plugin in _get_plugins(self):
            plugin._init(self, endness, instruction_endness)

        if endness == Endness.BE:
            self.memory_endness = Endness.BE
            self.register_endness = Endness.BE
            self.ret_instruction = reverse_ends(self.ret_instruction)
            self.nop_instruction = reverse_ends(self.nop_instruction)

    @cached_property
    def default_register_values(self):
        return [(r.name,) + r.default_value for r in self.register_list if r.default_value is not None]

    @cached_property
    def entry_register_values(self):
        return {r.name: r.linux_entry_value for r in self.register_list if r.linux_entry_value is not None}

    @cached_property
    def default_symbolic_registers(self):
        return [r.name for r in self.register_list if r.general_purpose]

    @cached_property
    def persistent_regs(self):
        return [r.name for r in self.register_list if r.persistent]

    @cached_property
    def artificial_registers(self):
        return {r.name for r in self.register_list if r.artificial}

    def copy(self):
        """
        Produce a copy of this instance of this arch.
        """
        res = copy.copy(self)
        for plugin in _get_plugins(self):
            plugin._prep_copy(res)
        return res

    def __repr__(self):
        return f"<Arch {self.name} ({self.memory_endness[-2:]})>"

    def __hash__(self):
        return hash((self.name, self.bits, self.memory_endness))

    def __eq__(self, other):
        if not isinstance(other, Arch):
            return False
        return self.name == other.name and self.bits == other.bits and self.memory_endness == other.memory_endness

    def __ne__(self, other):
        return not self == other

    def __getstate__(self):
        for plugin in _get_plugins(self):
            plugin._prep_getstate(self)
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)

    def get_register_by_name(self, reg_name):
        """
        Return the Register object associated with the given name.
        This includes subregisters.

        For example, if you are operating in a platform-independent
        setting, and wish to address "whatever the stack pointer is"
        you could pass 'sp' here, and get Register(...r13...) back
        on an ARM platform.
        """
        for r in self.register_list:
            if reg_name == r.name or reg_name in r.alias_names:
                return r
        return None

    def get_default_reg_value(self, register):
        if register == "sp" and hasattr(self, "sp_offset"):  # hack
            # Convert it to the corresponding register name
            registers = [r for r, v in self.registers.items() if v[0] == self.sp_offset]
            if len(registers) > 0:
                register = registers[0]
            else:
                return None
        for reg, val, _, _ in self.default_register_values:
            if reg == register:
                return val
        return None

    def struct_fmt(self, size=None, signed=False, endness=None):
        """
        Produce a format string for use in python's ``struct`` module to decode a single word.

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param str endness: The endian to use in packing/unpacking. Defaults to memory endness
        :return str:        A format string with an endness modifier and a single format character
        """
        if size is None:
            size = self.bytes
        if endness is None:
            endness = self.memory_endness

        if endness == Endness.BE:
            fmt_end = ">"
        elif endness == Endness.LE:
            fmt_end = "<"
        elif endness == Endness.ME:
            raise ValueError("Please don't middle-endian at me, I'm begging you")
        else:
            raise ValueError("Invalid endness value: %r" % endness)

        if size == 8:
            fmt_size = "Q"
        elif size == 4:
            fmt_size = "I"
        elif size == 2:
            fmt_size = "H"
        elif size == 1:
            fmt_size = "B"
        else:
            raise ValueError("Invalid size: Must be a integer power of 2 less than 16")

        if signed:
            fmt_size = fmt_size.lower()

        return fmt_end + fmt_size

    # e.g. sizeof['int'] = 32
    sizeof = {}

    def translate_dynamic_tag(self, tag):
        try:
            return self.dynamic_tag_translation[tag]
        except KeyError:
            if isinstance(tag, int):
                log.error("Please look up and add dynamic tag type %#x for %s", tag, self.name)
            return tag

    def translate_symbol_type(self, tag):
        try:
            return self.symbol_type_translation[tag]
        except KeyError:
            if isinstance(tag, int):
                log.error("Please look up and add symbol type %#x for %s", tag, self.name)
            return tag

    # Determined by watching the output of strace ld-linux.so.2 --list --inhibit-cache
    def library_search_path(self, pedantic=False):
        """
        A list of paths in which to search for shared libraries.
        """

        def subfunc(x):
            return x.replace("${TRIPLET}", self.triplet).replace("${ARCH}", self.linux_name)

        path = ["/lib/${TRIPLET}/", "/usr/lib/${TRIPLET}/", "/lib/", "/usr/lib", "/usr/${TRIPLET}/lib/"]
        if self.bits == 64:
            path.append("/usr/${TRIPLET}/lib64/")
            path.append("/usr/lib64/")
            path.append("/lib64/")
        elif self.bits == 32:
            path.append("/usr/${TRIPLET}/lib32/")
            path.append("/usr/lib32/")
            path.append("/lib32/")

        if pedantic:
            path = sum([[x + "tls/${ARCH}/", x + "tls/", x + "${ARCH}/", x] for x in path], [])
        return list(map(subfunc, path))

    def m_addr(self, addr, *args, **kwargs):
        """
        Given the address of some code block, convert it to the address where this block
        is stored in memory. The memory address can also be referred to as the "real" address.

        :param addr:    The address to convert.
        :return:        The "real" address in memory.
        :rtype:         int
        """
        return addr

    def x_addr(self, addr, *args, **kwargs):
        """
        Given the address of some code block, convert it to the value that should be assigned
        to the instruction pointer register in order to execute the code in that block.

        :param addr:    The address to convert.
        :return:        The "execution" address.
        :rtype:         int
        """
        return addr

    def is_thumb(self, addr):  # pylint:disable=unused-argument
        """
        Return True, if the address is the THUMB address. False otherwise.

        For non-ARM architectures this method always returns False.

        :param addr:    The address to check.
        :return:        Whether the given address is the THUMB address.
        """
        return False

    address_types = (int,)
    function_address_types = (int,)

    # various names
    name: str
    qemu_name = None
    ida_processor = None
    linux_name = None
    triplet = None

    # instruction stuff
    max_inst_bytes = None
    ret_instruction = b""
    nop_instruction = b""
    instruction_alignment = None

    # memory stuff
    bits = None
    memory_endness = Endness.LE
    register_endness = Endness.LE
    stack_change = None

    branch_delay_slot = False

    function_prologs = set()
    function_epilogs = set()

    call_pushes_ret = False
    initial_sp = 0x7FFF0000

    # Difference of the stack pointer after a call instruction (or its equivalent) is executed
    call_sp_fix = 0

    stack_size = 0x8000000

    # Register information
    register_list: List[Register] = []
    concretize_unique_registers = (
        set()
    )  # this is a list of registers that should be concretized, if unique, at the end of each block

    lib_paths = []
    reloc_s_a = []
    reloc_b_a = []
    reloc_s = []
    reloc_copy = []
    reloc_tls_mod_id = []
    reloc_tls_doffset = []
    reloc_tls_offset = []
    dynamic_tag_translation = {}
    symbol_type_translation = {}
    got_section_name = ""


arch_id_map = []

_all_arches = []


def all_arches():
    for x in _all_arches:
        yield x()


def register_arch(regexes, bits, endness, my_arch):
    """
    Register a new architecture.
    Architectures are loaded by their string name using ``arch_from_id()``, and
    this defines the mapping it uses to figure it out.
    Takes a list of regular expressions, and an Arch class as input.

    :param regexes: List of regular expressions (str or SRE_Pattern)
    :type regexes: list
    :param bits: The canonical "bits" of this architecture, ex. 32 or 64
    :type bits: int
    :param endness: The "endness" of this architecture.  Use Endness.LE, Endness.BE, Endness.ME, "any", or None if the
                    architecture has no intrinsic endianness.
    :type endness: str or None
    :param class my_arch:
    :return: None
    """
    if not isinstance(regexes, list):
        raise TypeError("regexes must be a list")
    for rx in regexes:
        if not isinstance(rx, str) and not isinstance(rx, re._pattern_type):
            raise TypeError("Each regex must be a string or compiled regular expression")
        try:
            re.compile(rx)
        except re.error as e:
            raise ValueError("Invalid Regular Expression %s" % rx) from e
    # if not isinstance(my_arch,Arch):
    #    raise TypeError("Arch must be a subclass of archinfo.Arch")
    if not isinstance(bits, int):
        raise TypeError("Bits must be an int")
    if endness is not None:
        if endness not in (Endness.BE, Endness.LE, Endness.ME, "any"):
            raise TypeError("Endness must be Endness.BE, Endness.LE, or 'any'")
    arch_id_map.append((regexes, bits, endness, my_arch))
    if endness == "any":
        _all_arches.append(partial(my_arch, Endness.BE))
        _all_arches.append(partial(my_arch, Endness.LE))
    else:
        _all_arches.append(partial(my_arch, endness))


class ArchNotFound(Exception):
    pass


def arch_from_id(ident, endness="any", bits="") -> Arch:
    """
    Take our best guess at the arch referred to by the given identifier, and return an instance of its class.

    You may optionally provide the ``endness`` and ``bits`` parameters (strings) to help this function out.
    """
    if bits == 64 or (isinstance(bits, str) and "64" in bits):
        bits = 64
    elif isinstance(bits, str) and "32" in bits:
        bits = 32
    elif not bits and "64" in ident:
        bits = 64
    elif not bits and "32" in ident:
        bits = 32

    endness = endness.lower()
    if "lit" in endness:
        endness = Endness.LE
    elif "big" in endness:
        endness = Endness.BE
    elif "lsb" in endness:
        endness = Endness.LE
    elif "msb" in endness:
        endness = Endness.BE
    elif "le" in endness:
        endness = Endness.LE
    elif "be" in endness:
        endness = Endness.BE
    elif "l" in endness:
        endness = "unsure"
    elif "b" in endness:
        endness = "unsure"
    else:
        endness = "unsure"
    ident = ident.lower()
    cls = None
    aendness = ""
    for arxs, abits, aendness, acls in arch_id_map:
        found_it = False
        for rx in arxs:
            if re.search(rx, ident):
                found_it = True
                break
        if not found_it:
            continue
        if bits and bits != abits:
            continue
        if aendness == "any" or endness == aendness or endness == "unsure":
            cls = acls
            break
    if not cls:
        raise ArchNotFound(
            f"Can't find architecture info for architecture {ident} with {repr(bits)} bits and {endness} endness"
        )
    if endness == "unsure":
        if aendness == "any":
            # We really don't care, use default
            return cls()
        else:
            # We're expecting the ident to pick the endness.
            # ex. 'armeb' means obviously this is Iend_BE
            return cls(aendness)
    else:
        return cls(endness)


def reverse_ends(string):
    count = (len(string) + 3) // 4
    ise = "I" * count
    string += b"\x00" * (count * 4 - len(string))
    return _struct.pack(">" + ise, *_struct.unpack("<" + ise, string))


def get_host_arch():
    """
    Return the arch of the machine we are currently running on.
    """
    return arch_from_id(_platform.machine())
