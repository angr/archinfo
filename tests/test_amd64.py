from archinfo.arch import Endness
from nose.tools import raises
from archinfo import ArchAMD64, ArchError
import nose.tools

try:
    import capstone as _capstone
except ImportError:
    _capstone = None


def test_arch_amd64():
    endness = Endness.LE
    assert ArchAMD64(endness)


@raises(ArchError)
def test_arch_amd64_passes():
    endness = Endness.BE
    ArchAMD64(endness)


def test_capstone_x86_syntax():
    inst_1 = ArchAMD64(endness=Endness.LE)
    nose.tools.assert_is_none(inst_1.capstone_x86_syntax)
    inst_1.capstone_x86_syntax = 'intel'
    nose.tools.assert_equal(inst_1.capstone_x86_syntax, 'intel')
    inst_1.capstone_x86_syntax = 'at&t'
    nose.tools.assert_equal(inst_1.capstone_x86_syntax, 'at&t')


# Test raises one of expected exceptions to pass.
@raises(ArchError)
def test_capstone_x86_syntax_fails_1():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.capstone_x86_syntax = 'at&'
    assert inst_1.capstone_x86_syntax


@raises(ArchError)
def test_capstone_x86_syntax_fails_2():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.capstone_x86_syntax = 'int'
    assert inst_1.capstone_x86_syntax


def test_keystone_x86_syntax():
    inst_1 = ArchAMD64(endness=Endness.LE)
    nose.tools.assert_is_none(inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'intel'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'intel')
    inst_1.keystone_x86_syntax = 'at&t'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'at&t')
    inst_1.keystone_x86_syntax = 'nasm'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'nasm')
    inst_1.keystone_x86_syntax = 'masm'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'masm')
    inst_1.keystone_x86_syntax = 'gas'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'gas')
    inst_1.keystone_x86_syntax = 'radix16'
    nose.tools.assert_equal(inst_1.keystone_x86_syntax, 'radix16')


# Test raises one of expected exceptions to pass.
@raises(ArchError)
def test_keystone_x86_syntax_fails_1():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'inte'
    assert inst_1.keystone_x86_syntax


@raises(ArchError)
def test_keystone_x86_syntax_fails_2():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'at'
    assert inst_1.keystone_x86_syntax


@raises(ArchError)
def test_keystone_x86_syntax_fails_3():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'na'
    assert inst_1.keystone_x86_syntax


@raises(ArchError)
def test_keystone_x86_syntax_fails_4():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'ma'
    assert inst_1.keystone_x86_syntax
