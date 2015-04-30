''' This class is responsible for architecture-specific things such as call emulation and so forth. '''

import capstone as _capstone
import struct as _struct
from elftools.elf.elffile import ELFFile as _ELFFile

class Arch(object):
    def __init__(self, endness):
        if endness not in ('Iend_LE', 'Iend_BE'):
            raise ArchError('Must pass a valid VEX endness: "Iend_LE" or "Iend_BE"')
        if endness == 'Iend_BE':
            self.vex_endness = "VexEndnessBE"
            self.memory_endness = 'Iend_BE'
            self.register_endness = 'Iend_BE'
            self.cs_mode -= _capstone.CS_MODE_LITTLE_ENDIAN
            self.cs_mode += _capstone.CS_MODE_BIG_ENDIAN
            self.ret_instruction = reverse_ends(self.ret_instruction)
            self.nop_instruction = reverse_ends(self.nop_instruction)

    def gather_info_from_state(self, state):
        info = {}
        for reg in self.persistent_regs:
            info[reg] = state.reg_expr(reg)
        return info

    def prepare_state(self, state, info=None):
        if info is not None:
            # TODO: Only do this for PIC!
            for reg in self.persistent_regs:
                if reg in info:
                    state.set_reg(reg, info[reg])

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
        return self.bits/8

    @property
    def capstone(self):
        if self._cs is None:
            self._cs = _capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.detail = True
        return self._cs

    # various names
    name = None
    vex_arch = None
    qemu_name = None
    ida_processor = None

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
    vex_endness = 'VexEndnessLE'
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
    call_pushes_ret = False
    initial_sp = 0xffff0000

    # Difference of the stack pointer after a call instruction (or its equivalent) is executed
    call_sp_fix = 0

    stack_size = 0x8000000

    # Register information
    default_register_values = [ ]
    entry_register_values = { }
    default_symbolic_registers = [ ]
    registers = { }
    argument_registers = { }
    persistent_regs = [ ]
    concretize_unique_registers = set() # this is a list of registers that should be concretized, if unique, at the end of each block



def arch_from_id(ident, endness, bits):
    if bits == 64 or (isinstance(bits, str) and '64' in bits):
        bits = 64
    else:
        bits = 32

    endness = endness.lower()
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
    elif 'b' in endness:
        endness = 'Iend_BE'
    else:
        endness = 'Iend_LE'

    if 'ppc64' in ident or 'powerpc64' in ident:
        return ArchPPC64(endness)
    elif 'ppc' in ident or 'powerpc' in ident:
        if bits == 64:
            return ArchPPC64(endness)
        return ArchPPC32(endness)
    elif 'mips' in ident:
        return ArchMIPS32(endness)
    elif 'arm' in ident:
        return ArchARM(endness)
    elif 'amd64' in ident or ('x86' in ident and '64' in ident) or 'x64' in ident:
        return ArchAMD64('Iend_LE')
    elif 'i386' in ident or 'x86' in ident or 'metapc' in ident:
        if bits == 64:
            return ArchAMD64('Iend_LE')
        return ArchX86('Iend_LE')

    raise ArchError("Could not parse out arch!")

def arch_from_binary(filename):
    try:
        reader = _ELFFile(open(filename))
        return arch_from_id(reader.header.e_machine,
                            reader.header.e_ident.EI_DATA,
                            reader.header.e_ident.EI_CLASS)
    except OSError:
        pass

    raise ArchError("Could not determine architecture")


def reverse_ends(string):
    ise = 'I'*(len(string)/4)
    return _struct.pack('>' + ise, *_struct.unpack('<' + ise, string))


from .arch_amd64    import ArchAMD64
from .arch_x86      import ArchX86
from .arch_arm      import ArchARM
from .arch_ppc32    import ArchPPC32
from .arch_ppc64    import ArchPPC64
from .arch_mips32   import ArchMIPS32
from .archerror     import ArchError
