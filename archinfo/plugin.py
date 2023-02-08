from typing import TYPE_CHECKING, List, Dict, Type
import logging

from .arch import Arch, REGISTERED_ARCH_PLUGINS, REGISTERED_REGISTER_PLUGINS
from .register import Register

if TYPE_CHECKING:
    from .arch import Endness

log = logging.getLogger(__name__)


class ArchPlugin:
    _new_registers: List[Register]
    _patched_registers: List["RegisterPlugin"]
    _children: Dict[str, Type["ArchPlugin"]]

    def __init_subclass__(cls, patches=None, **kwargs):
        if patches is None or not issubclass(patches, Arch):
            raise TypeError("Cannot create an ArchPlugin subclass without specifying which arch class to patch")

        REGISTERED_ARCH_PLUGINS[patches].append(cls)

        unused = object()
        for k, v in vars(cls).items():
            if k.startswith(f"_{cls.__name__}__"):
                continue
            orig = getattr(patches, k, unused)
            if orig is unused or any(hasattr(base, k) for base in cls.__bases__):
                setattr(patches, k, v)
            else:
                raise TypeError(f"Conflict between plugin and patchee ({k})")

    @classmethod
    def _init(cls, arch: Arch, endness: "Endness", instruction_endness: "Endness"):
        pass

    @classmethod
    def _prep_getstate(cls, arch: Arch):
        pass

    @classmethod
    def _prep_copy(cls, arch: Arch):
        pass


class RegisterPlugin:
    def __init__(self, name):
        self.name = name

    def __init_subclass__(cls, **kwargs):
        REGISTERED_REGISTER_PLUGINS.append(cls)

    def _fill(self, old_reg: Register):
        for k, v in vars(self).items():
            if k in vars(Register) or hasattr(old_reg, k):
                continue
            setattr(old_reg, k, v)
