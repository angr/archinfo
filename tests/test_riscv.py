from archinfo.arch import Endness
from nose.tools import raises
from archinfo import ArchRISCV, ArchError
import nose.tools


def test_arch_riscv():
    endness = Endness.LE
    assert ArchRISCV(endness)

@raises(ArchError)
def test_arch_riscv_passes():
    endness = Endness.BE
    ArchRISCV(endness)
