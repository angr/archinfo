from archinfo.arch import Endness
from nose.tools import raises
from archinfo import ArchAMD64
import nose.tools

def test_arch_amd64():
    endness = Endness.LE
    assert ArchAMD64(endness)


def test_arch_amd64_passes():
    endness = Endness.LE
    nose.tools.assert_raises(Exception, ArchAMD64(endness))


@raises(Exception)
def test_arch_amd64_fails():
    endness = Endness.BE
    nose.tools.assert_raises(Exception, ArchAMD64(endness))


def test_capstone_x86_syntax():
    inst_1 = ArchAMD64(endness=Endness.LE)
    nose.tools.assert_is_none(inst_1.capstone_x86_syntax)
    inst_1.capstone_x86_syntax = 'intel'
    nose.tools.assert_equal(inst_1.capstone_x86_syntax, 'intel')
    inst_1.capstone_x86_syntax = 'at&t'
    nose.tools.assert_equal(inst_1.capstone_x86_syntax, 'at&t')


def test_capstone_x86_syntax_passes():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.capstone_x86_syntax = 'intel'
    nose.tools.assert_raises(Exception, inst_1.capstone_x86_syntax)
    inst_1.capstone_x86_syntax = 'at&t'
    nose.tools.assert_raises(Exception, inst_1.capstone_x86_syntax)


# Test raises one of expected exceptions to pass.
@raises(Exception)
def test_capstone_x86_syntax_fails_1():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.capstone_x86_syntax = 'at&'
    nose.tools.assert_raises(Exception, inst_1.capstone_x86_syntax)


@raises(Exception)
def test_capstone_x86_syntax_fails_2():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.capstone_x86_syntax = 'int'
    nose.tools.assert_raises(Exception, inst_1.capstone_x86_syntax)


def test_configure_capstone():
    pass


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


def test_keystone_x86_syntax_passes():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'intel'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'at&t'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'nasm'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'masm'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'gas'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)
    inst_1.keystone_x86_syntax = 'radix16'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)


# Test raises one of expected exceptions to pass.
@raises(Exception)
def test_keystone_x86_syntax_fails_1():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'inte'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)


@raises(Exception)
def test_keystone_x86_syntax_fails_2():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'at'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)


@raises(Exception)
def test_keystone_x86_syntax_fails_3():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'na'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)


@raises(Exception)
def test_keystone_x86_syntax_fails_4():
    inst_1 = ArchAMD64(endness=Endness.LE)
    inst_1.keystone_x86_syntax = 'ma'
    nose.tools.assert_raises(Exception, inst_1.keystone_x86_syntax)


def test_configure_keystone():
    pass
