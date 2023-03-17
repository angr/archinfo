from typing import List, Tuple, Optional, Iterable, Union, TypeVar, TYPE_CHECKING, Type, Dict, cast
from functools import singledispatchmethod

from .types import RegisterOffset, RegisterName, register_range

if TYPE_CHECKING:
    from .arch import Arch

__all__ = ("Endness", "Register", "register_range")


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
        name: RegisterName,
        size: int,
        subregisters: Optional[List[Tuple[RegisterName, int, int]]] = None,
        alias_names: Optional[Tuple[str, ...]] = None,
        general_purpose: bool = False,
        floating_point: bool = False,
        vector: bool = False,
        argument: bool = False,
        persistent: bool = False,
        default_value: Optional[Tuple[int, bool, Optional[str]]] = None,
        linux_entry_value: Union[str, int, None] = None,
        concretize_unique: bool = False,
        concrete: bool = True,
        artificial: bool = False,
        disposition: str = '',
    ):
        self.name: RegisterName = name
        self.size: int = size
        self.subregisters: List[Tuple[RegisterName, int, int]] = [] if subregisters is None else subregisters
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
        self.disposition = disposition

    def __repr__(self):
        return f"<Register {self.name}>"


REGISTER_FILES: Dict[str, Type["RegisterFile"]] = {}


class RegisterFile:
    """
    A mapping from registers to offsets within a flat address space.

    Additionally, contains caches for several ways to look up registers using this mapping.
    """

    def __init__(self, arch: "Arch"):
        offsets = [(reg, self._extract_offset(reg)) for reg in arch.register_list]
        self.name_to_offset: Dict[RegisterName, RegisterOffset] = {
            reg.name: offset for reg, offset in offsets if offset is not None
        }
        self.offset_to_name: Dict[RegisterOffset, RegisterName] = {
            offset: reg.name for reg, offset in offsets if offset is not None
        }
        self.offset_and_size_to_name: Dict[Tuple[RegisterOffset, int], RegisterName] = {
            (offset, reg.size): reg.name for reg, offset in offsets if offset is not None
        }
        self.offset_and_size_to_name.update(
            {
                (RegisterOffset(offset + suboffset), subsize): subname
                for reg, offset in offsets
                if offset is not None
                for subname, suboffset, subsize in reg.subregisters
            }
        )
        self.offset_and_size_to_parent: Dict[Tuple[RegisterOffset, int], Tuple[RegisterOffset, int]] = {
            (RegisterOffset(offset + suboffset), subsize): (offset, reg.size)
            for reg, offset in offsets
            if offset is not None
            for subname, suboffset, subsize in reg.subregisters
        }
        # TODO special hacks for x86 bp, sp, ip?

        self.concretize_unique_offsets = {offset for reg, offset in offsets if reg.concretize_unique}
        self.artificial_offsets = [
            RegisterOffset(sub_offset)
            for reg, offset in offsets
            if offset is not None and reg.artificial
            for sub_offset in range(offset, reg.size)
        ]

        self.ip_offset = None
        self.sp_offset = None
        self.bp_offset = None
        self.lr_offset = None
        self.syscall_num_offset = None
        self.ret_offset = None
        self.fp_ret_offset = None

    def __init_subclass__(cls, *, name: Optional[str] = None):
        if name is None:
            return
        if name in REGISTER_FILES:
            raise TypeError(f"Incompatible register files definitions: two named {name}")
        REGISTER_FILES[name] = cls

    def _extract_offset(self, reg: Register) -> Optional[RegisterOffset]:
        raise NotImplementedError


T = TypeVar("T", bound=RegisterFile)


class RegisterFileLookup:
    def __init__(self, arch: "Arch"):
        self.arch = arch
        self._lookup_by_cls: Dict[Type[RegisterFile], RegisterFile] = {}
        self._lookup_by_name: Dict[str, RegisterFile] = {}

    @singledispatchmethod
    def __getitem__(self, k):
        raise TypeError(type(k))

    @__getitem__.register
    def _(self, k: str) -> RegisterFile:
        inst = self._lookup_by_name.get(k, None)
        if inst is None:
            cls = REGISTER_FILES.get(k, None)
            if cls is None:
                raise IndexError(f"No known register file named {k}")
            self._lookup_by_name[k] = inst = self[cls]
        return inst

    @__getitem__.register(type)
    def _(self, k: Type[T]) -> T:
        inst = self._lookup_by_cls.get(k, None)
        if inst is None:
            try:
                self._lookup_by_cls[k] = inst = k(self.arch)
            except NotImplementedError as e:
                raise IndexError(f"Register file {k} is not implemented for {self.arch}") from e
        else:
            inst = cast(T, inst)
        return inst

    def __setitem__(self, k: str, v: RegisterFile):
        self._lookup_by_name[k] = v
        self._lookup_by_cls[type(v)] = v


class DefaultRegisterFile(RegisterFile, name="default"):
    """
    A register file which allocates its own offsets for absolutely everything.
    """

    def __init__(self, registers):
        self._next_offset = 0
        super().__init__(registers)

    def _extract_offset(self, reg):
        result = self._next_offset
        self._next_offset += reg.size
        return RegisterOffset(result)
