from typing import List, Tuple

from .types import RegisterOffset, RegisterName


class Endness:  # pylint: disable=no-init
    """Endness specifies the byte order for integer values

    :cvar LE:      little endian, least significant byte is stored at lowest address
    :cvar BE:      big endian, most significant byte is stored at lowest address
    :cvar ME:      Middle-endian. Yep.
    """

    LE = "Iend_LE"
    BE = "Iend_BE"
    ME = "Iend_ME"


class Register:
    """
    A collection of information about a register. Each different architecture
    has its own list of registers, which is the base for all other
    register-related collections.

    It is, just like for Arch object, assumed that the information is compatible
    with PyVEX.

    :ivar str  name: The name of the register
    :ivar int  size: The size of the register (in bytes)
    :ivar list subregisters: The list of subregisters in the form (name, offset from base, size)
    :ivar tuple alias_names: The list of possible alias names
    :ivar bool general_purpose: Whether this is a general purpose register
    :ivar bool floating_point: Whether this is a floating-point register
    :ivar bool vector: Whether this is a vector register
    :ivar bool argument: Whether this is an argument register
    :ivar bool persistent: Whether this is a persistent register
    :ivar tuple default_value:
    :ivar int, str linux_entry_value:
    :ivar bool concretize_unique: Whether this register should be concretized, if unique, at the end of each block
    :ivar bool concrete: Whether this register should be considered during the synchronization of the concrete execution
                         of the process
    :ivar bool artificial: Whether this register is an artificial register added by some IR or IL.
    """

    def __init__(
        self,
        name,
        size,
        subregisters=None,
        alias_names=None,
        general_purpose=False,
        floating_point=False,
        vector=False,
        argument=False,
        persistent=False,
        default_value=None,
        linux_entry_value=None,
        concretize_unique=False,
        concrete=True,
        artificial=False,
    ):
        self.name: RegisterName = name
        self.size: int = size
        self.subregisters: List[Tuple[RegisterName, RegisterOffset, int]] = [] if subregisters is None else subregisters
        self.alias_names = () if alias_names is None else alias_names
        self.general_purpose = general_purpose
        self.floating_point = floating_point
        self.vector = vector
        self.argument = argument
        self.persistent = persistent
        self.default_value = default_value
        self.linux_entry_value = linux_entry_value
        self.concretize_unique = concretize_unique
        self.concrete = concrete
        self.artificial = artificial

    def __repr__(self):
        return f"<Register {self.name}>"
