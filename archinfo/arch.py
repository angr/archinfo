import capstone as _capstone
import struct as _struct

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None

try:
    import unicorn as _unicorn
except ImportError:
    _unicorn = None

import logging
l = logging.getLogger('archinfo.arch')
l.addHandler(logging.NullHandler())

class Arch(object):
    """
    Represent an architecture. This class is responsible for architecture-specific things such as call emulation.

    :ivar name: The name of the architecture.
    :type name: str

    """
    def __init__(self, endness):
        if endness not in ('Iend_LE', 'Iend_BE'):
            raise ArchError('Must pass a valid VEX endness: "Iend_LE" or "Iend_BE"')

        if _pyvex:
            self.vex_archinfo = _pyvex.default_vex_archinfo()
        if endness == 'Iend_BE':
            if self.vex_archinfo:
                self.vex_archinfo['endness'] = _pyvex.vex_endness_from_string('VexEndnessBE')
            self.memory_endness = 'Iend_BE'
            self.register_endness = 'Iend_BE'
            self.cs_mode -= _capstone.CS_MODE_LITTLE_ENDIAN
            self.cs_mode += _capstone.CS_MODE_BIG_ENDIAN
            self.ret_instruction = reverse_ends(self.ret_instruction)
            self.nop_instruction = reverse_ends(self.nop_instruction)

        # unicorn specific stuff
        if self.uc_mode is not None:
            if endness == 'Iend_BE':
                self.uc_mode -= _unicorn.UC_MODE_LITTLE_ENDIAN
                self.uc_mode += _unicorn.UC_MODE_BIG_ENDIAN
            self.uc_regs = { }
            # map register names to unicorn const
            for r in self.register_names.itervalues():
                reg_name = self.uc_prefix + 'REG_' + r.upper()
                if hasattr(self.uc_const, reg_name):
                    self.uc_regs[r] = getattr(self.uc_const, reg_name)

    def copy(self):
        new_arch = type(self)(self.memory_endness)
        new_arch.vex_archinfo = self.vex_archinfo.copy()

        return new_arch

    def __repr__(self):
        return '<Arch %s (%s)>' % (self.name, self.memory_endness[-2:])

    def __eq__(self, other):
        if not isinstance(other, Arch):
            return False
        return  self.name == other.name and \
                self.bits == other.bits and \
                self.memory_endness == other.memory_endness

    def __ne__(self, other):
        return not self == other

    def __getstate__(self):
        self._cs = None
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)

    def gather_info_from_state(self, state):
        info = {}
        for reg in self.persistent_regs:
            info[reg] = state.registers.load(reg)
        return info

    def prepare_state(self, state, info=None):
        if info is not None:
            # TODO: Only do this for PIC!
            for reg in self.persistent_regs:
                if reg in info:
                    state.registers.store(reg, info[reg])

        return state

    def get_default_reg_value(self, register):
        if register == 'sp':
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

    def struct_fmt(self, size=None):
        fmt = ""
        if size is None:
            size = self.bits

        if self.memory_endness == "Iend_BE":
            fmt += ">"
        else:
            fmt += "<"

        if size == 64:
            fmt += "Q"
        elif size == 32:
            fmt += "I"
        elif size == 16:
            fmt += "H"
        elif size == 8:
            fmt += "B"
        else:
            raise ValueError("Invalid size: Must be a muliple of 8")

        return fmt

    @property
    def bytes(self):
        """
        Return the standard word size in bytes
        """
        return self.bits/8

    # e.g. sizeof['int'] = 4
    sizeof = {}

    @property
    def capstone(self):
        if self.cs_arch is None:
            raise ArchError("Arch %s does not support disassembly with capstone" % self.name)
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.detail = True
        return self._cs

    @property
    def unicorn(self):
        if _unicorn is None or self.uc_arch is None:
            raise ArchError("Arch %s does not support with unicorn" % self.name)
        # always create a new unicorn instance
        return _unicorn.Uc(self.uc_arch, self.uc_mode)

    def translate_dynamic_tag(self, tag):
        try:
            return self.dynamic_tag_translation[tag]
        except KeyError:
            if isinstance(tag, (int, long)):
                l.error("Please look up and add dynamic tag type %#x for %s", tag, self.name)
            return tag

    def translate_symbol_type(self, tag):
        try:
            return self.symbol_type_translation[tag]
        except KeyError:
            if isinstance(tag, (int, long)):
                l.error("Please look up and add symbol type %#x for %s", tag, self.name)
            return tag

    def translate_register_name(self, offset):
        try:
            return self.register_names[offset]
        except KeyError:
            return str(offset)

    # Determined by watching the output of strace ld-linux.so.2 --list --inhibit-cache
    def library_search_path(self, pedantic=False):
        subfunc = lambda x: x.replace('${TRIPLET}', self.triplet).replace('${ARCH}', self.linux_name)
        path = ['/lib/${TRIPLET}/', '/usr/lib/${TRIPLET}/', '/lib/', '/usr/lib', '/usr/${TRIPLET}/lib/']
        if self.bits == 64:
            path.append('/usr/${TRIPLET}/lib64/')
            path.append('/usr/lib64/')
            path.append('/lib64/')
        elif self.bits == 32:
            path.append('/usr/${TRIPLET}/lib32/')
            path.append('/usr/lib32/')

        if pedantic:
            path = sum([[x + 'tls/${ARCH}/', x + 'tls/', x + '${ARCH}/', x] for x in path], [])
        return map(subfunc, path)

    # various names
    name = None
    vex_arch = None
    qemu_name = None
    ida_processor = None
    linux_name = None
    triplet = None

    # instruction stuff
    max_inst_bytes = None
    ret_instruction = ''
    nop_instruction = ''
    instruction_alignment = None

    # register ofsets
    ip_offset = None
    sp_offset = None
    bp_offset = None
    ret_offset = None

    # memory stuff
    bits = None
    memory_endness = 'Iend_LE'
    register_endness = 'Iend_LE'
    stack_change = None

    # is it safe to cache IRSBs?
    cache_irsb = True

    function_prologs = set()
    function_epilogs = set()

    # Capstone stuff
    cs_arch = None
    cs_mode = None
    _cs = None

    # Unicorn stuff
    uc_arch = None
    uc_mode = None
    uc_const = None
    uc_prefix = None
    uc_regs = None

    call_pushes_ret = False
    initial_sp = 0x7fff0000

    # Difference of the stack pointer after a call instruction (or its equivalent) is executed
    call_sp_fix = 0

    stack_size = 0x8000000

    # Register information
    default_register_values = [ ]
    entry_register_values = { }
    default_symbolic_registers = [ ]
    registers = { }
    register_names = { }
    argument_registers = { }
    persistent_regs = [ ]
    concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block

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
    got_section_name = ''

    vex_archinfo = None

def arch_from_id(ident, endness='', bits=''):
    if bits == 64 or (isinstance(bits, str) and '64' in bits):
        bits = 64
    else:
        bits = 32

    endness = endness.lower()
    endness_unsure = False
    if 'lit' in endness:
        endness = 'Iend_LE'
    elif 'big' in endness:
        endness = 'Iend_BE'
    elif 'lsb' in endness:
        endness = 'Iend_LE'
    elif 'msb' in endness:
        endness = 'Iend_BE'
    elif 'le' in endness:
        endness = 'Iend_LE'
    elif 'be' in endness:
        endness = 'Iend_BE'
    elif 'l' in endness:
        endness = 'Iend_LE'
        endness_unsure = True
    elif 'b' in endness:
        endness = 'Iend_BE'
        endness_unsure = True
    else:
        endness = 'Iend_LE'
        endness_unsure = True

    ident = ident.lower()
    if 'ppc64' in ident or 'powerpc64' in ident:
        if endness_unsure:
            endness = 'Iend_BE'
        return ArchPPC64(endness)
    elif 'ppc' in ident or 'powerpc' in ident:
        if endness_unsure:
            endness = 'Iend_BE'
        if bits == 64:
            return ArchPPC64(endness)
        return ArchPPC32(endness)
    elif 'mips' in ident:
        if 'mipsel' in ident:
            if bits == 64:
                return ArchMIPS64('Iend_LE')
            return ArchMIPS32('Iend_LE')
        if endness_unsure:
            if bits == 64:
                return ArchMIPS64('Iend_BE')
            return ArchMIPS32('Iend_BE')
        if bits == 64:
            return ArchMIPS64(endness)
        return ArchMIPS32(endness)
    elif 'arm' in ident or 'thumb' in ident:
        if endness_unsure:
            if 'l' in ident or 'le' in ident:
                endness = 'Iend_LE'
            elif 'b' in ident or 'be' in ident:
                endness = 'Iend_BE'
        if bits == 64:
            return ArchAArch64(endness)
        return ArchARM(endness)
    elif 'aarch' in ident:
        return ArchAArch64(endness)
    elif 'amd64' in ident or ('x86' in ident and '64' in ident) or 'x64' in ident:
        return ArchAMD64('Iend_LE')
    elif '386' in ident or 'x86' in ident or 'metapc' in ident:
        if bits == 64:
            return ArchAMD64('Iend_LE')
        return ArchX86('Iend_LE')

    raise ArchError("Could not parse out arch!")


def reverse_ends(string):
    ise = 'I'*(len(string)/4)
    return _struct.pack('>' + ise, *_struct.unpack('<' + ise, string))

# pylint: disable=unused-import
from .arch_amd64    import ArchAMD64
from .arch_x86      import ArchX86
from .arch_arm      import ArchARM, ArchARMEL, ArchARMHF
from .arch_aarch64  import ArchAArch64
from .arch_ppc32    import ArchPPC32
from .arch_ppc64    import ArchPPC64
from .arch_mips32   import ArchMIPS32
from .arch_mips64   import ArchMIPS64
from .archerror     import ArchError

all_arches = [
    ArchAMD64(), ArchX86(),
    ArchARM('Iend_LE'), ArchARM('Iend_BE'),
    ArchAArch64('Iend_LE'), ArchAArch64('Iend_BE'),
    ArchPPC32('Iend_LE'), ArchPPC32('Iend_BE'),
    ArchPPC64('Iend_LE'), ArchPPC64('Iend_BE'),
    ArchMIPS32('Iend_LE'), ArchMIPS32('Iend_BE'),
    ArchMIPS64('Iend_LE'), ArchMIPS64('Iend_BE')
]
