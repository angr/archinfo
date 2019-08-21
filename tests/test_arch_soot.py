from archinfo.arch import Endness
from nose.tools import raises
from archinfo.arch_soot import SootAddressDescriptor, SootMethodDescriptor, SootAddressTerminator, SootFieldDescriptor, SootClassDescriptor, SootNullConstant, SootArgument, ArchSoot
import nose.tools

def test_soot_method_descriptor():
    assert SootMethodDescriptor(class_name = 'abc', name = 'pqr', params = ('a','b'), soot_method = None, ret_type = None)


def test_repr():
    assert repr(SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a','b'))) == 'abc.abc(a, b)'


def test_eq():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.class_name, inst_2.class_name)
    nose.tools.assert_equal(inst_1.name, inst_2.name)
    nose.tools.assert_equal(inst_1.params, inst_2.params)


def test_ne():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name = 'xyz', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_not_equal(inst_1, inst_2)


def test_less_than_soot_method_descriptor():
    inst_1 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name='b', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1 < inst_2, True)

    inst_3 = SootMethodDescriptor(class_name='a', name = 'c', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_4 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_3 < inst_4, False)

    inst_5 = SootMethodDescriptor(class_name='a', name = 'a', params = ('4', '1'), soot_method = None, ret_type = None)
    inst_6 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_5 < inst_6, False)


def test_greater_than_soot_method_descriptor():
    inst_1 = SootMethodDescriptor(class_name='c', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1 > inst_2, True)

    inst_3 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_4 = SootMethodDescriptor(class_name='a', name = 'c', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_3 > inst_4, False)

    inst_5 = SootMethodDescriptor(class_name='a', name = 'a', params = ('5', '1'), soot_method = None, ret_type = None)
    inst_6 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_5 > inst_6, True)


def test_less_than_or_equal_to_soot_method_descriptor():
    inst_1 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name='a', name = 'c', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1 <= inst_2, True)

    inst_3 = SootMethodDescriptor(class_name='b', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_4 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_3 <= inst_4, False)


def test_greater_than_or_equal_to_soot_method_descriptor():
    inst_1 = SootMethodDescriptor(class_name='b', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_2 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1 >= inst_2, True)

    inst_3 = SootMethodDescriptor(class_name='a', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    inst_4 = SootMethodDescriptor(class_name='c', name = 'a', params = ('1', '1'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_3 >= inst_4, False)


def test_address():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'xyz', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_2 = SootAddressDescriptor(inst_1, block_idx = 1, stmt_idx = 2)
    nose.tools.assert_equal(inst_1.address(block_idx = 1, stmt_idx = 2), inst_2)
    nose.tools.assert_not_equal(inst_1.address(block_idx = 2, stmt_idx = 3), inst_2)


def test_fullname():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.fullname, 'abc.abc')
    inst_2 = SootMethodDescriptor(class_name = 'pqr', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_not_equal(inst_2.fullname, 'abc.abc')


def test_symbolic():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.symbolic, 3 > 4)
    nose.tools.assert_not_equal(inst_1.symbolic, 5 > 4)


def test_is_loaded():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.is_loaded, False)

    inst_2 = SootMethodDescriptor(class_name = 'abc', name = 'pqr', params = ('a', 'b'), soot_method = not None, ret_type = None)
    nose.tools.assert_equal(inst_2._soot_method, True)

    inst_3 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = not None, ret_type = None)
    nose.tools.assert_is_not_none(inst_3._soot_method)


def test_attrs():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.attrs, [])


def test_exceptions():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.exceptions, [])


def test_block_by_label():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'abc', params = ('a', 'b'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.block_by_label, None)


def test_addr():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'xyz', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_2 = SootAddressDescriptor(inst_1, block_idx = 0, stmt_idx = 0)
    nose.tools.assert_equal(inst_1.addr, inst_2)
    inst_3 = SootAddressDescriptor(inst_1, block_idx = 3, stmt_idx = 4)
    nose.tools.assert_not_equal(inst_1.addr, inst_3)


def test_matches_with_native_name():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'xyz', params = ('1', '2'), soot_method = None, ret_type = None)
    nose.tools.assert_equal(inst_1.matches_with_native_name(native_method='abc'), False)
    native_method = 'abc.__'
    nose.tools.assert_equal(inst_1.matches_with_native_name(native_method), False)

    native_method = '__abc'
    nose.tools.assert_equal(inst_1.matches_with_native_name(native_method), False)

    inst_2 = SootMethodDescriptor(class_name = 'pqr', name = 'ijk', params = ('1', '2'), soot_method = None, ret_type = None)
    native_method = 'Java_pqr_ijk'
    nose.tools.assert_equal(inst_2.matches_with_native_name(native_method), True)


@raises(Exception)
def test_matches_with_native_name_fails():
    inst_1 = SootMethodDescriptor(class_name = 'abc', name = 'xyz', params = ('1', '2'))
    native_method = '__abb__'
    nose.tools.assert_raises(Exception, inst_1.matches_with_native_name(native_method))
    native_method = '__abc____'
    nose.tools.assert_raises(Exception, inst_1.matches_with_native_name(native_method))


def test_soot_address_descriptor():
    method = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    assert SootAddressDescriptor(method, block_idx = 2, stmt_idx = 2)


@raises(ValueError)
def test_soot_address_descriptor_fails():
    nose.tools.assert_raises(ValueError, SootAddressDescriptor(method = None, block_idx = 1, stmt_idx = 2))


def test_repr_soot_address_descriptor():
    method = SootMethodDescriptor(class_name='abc', name = 'pqr', params = ('1', '2'), soot_method = None, ret_type = None)
    # stmt_idx = not None
    nose.tools.assert_equal(repr(SootAddressDescriptor(method, block_idx = 1, stmt_idx = not None)), '<abc.pqr(1, 2)+(1:1)>')
    # stmt_idx = None
    nose.tools.assert_equal(repr(SootAddressDescriptor(method, block_idx = 1, stmt_idx = None)), '<abc.pqr(1, 2)+(1:[0])>')


def test_eq_soot_address_descriptor():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_2 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = 2)
    inst_2 = SootAddressDescriptor(method_2, block_idx = 2, stmt_idx = 2)
    nose.tools.assert_equal(inst_1.method, inst_2.method)
    nose.tools.assert_equal(inst_1.block_idx, inst_2.block_idx)
    nose.tools.assert_equal(inst_1.stmt_idx, inst_2.stmt_idx)


def test_not_eq_soot_address_descriptor():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_2 = SootMethodDescriptor(class_name='pqr', name = 'pqr', params = ('3', '4'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = 2)
    inst_2 = SootAddressDescriptor(method_2, block_idx = 3, stmt_idx = 2)
    nose.tools.assert_not_equal(inst_1, inst_2)


def test_less_than_soot_address_descriptor():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = None)
    inst_2 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_1 < inst_2, True)

    inst_3 = SootAddressDescriptor(method_1, block_idx = 5, stmt_idx = None)
    inst_4 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_3 < inst_4, False)

    method_2 = SootMethodDescriptor(class_name='b', name = 'c', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_5 = SootAddressDescriptor(method_2, block_idx = 3, stmt_idx = 3)
    inst_6 = SootAddressDescriptor(method_2, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_5 < inst_6, False)

    method_3 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_4 = SootMethodDescriptor(class_name='pqr', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_7 = SootAddressDescriptor(method_3, block_idx = 3, stmt_idx = 3)
    inst_8 = SootAddressDescriptor(method_4, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_7 < inst_8, True)

    method_5 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_6 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('5', '2'), soot_method = None, ret_type = None)
    inst_9 = SootAddressDescriptor(method_5, block_idx = 3, stmt_idx = 3)
    inst_10 = SootAddressDescriptor(method_6, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_9 < inst_10, True)


def test_greater_than_soot_address_descriptor():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    inst_2 = SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = None)
    nose.tools.assert_equal(inst_1 > inst_2, True)

    inst_3 = SootAddressDescriptor(method_1, block_idx = 5, stmt_idx = None)
    inst_4 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_3 > inst_4, True)

    method_2 = SootMethodDescriptor(class_name='a', name = 'c', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_5 = SootAddressDescriptor(method_2, block_idx = 3, stmt_idx = 3)
    inst_6 = SootAddressDescriptor(method_2, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_5 > inst_6, False)

    method_3 = SootMethodDescriptor(class_name='xyz', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_4 = SootMethodDescriptor(class_name='pqr', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_7 = SootAddressDescriptor(method_3, block_idx = 3, stmt_idx = 3)
    inst_8 = SootAddressDescriptor(method_4, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_7 > inst_8, True)

    method_5 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    method_6 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('5', '2'), soot_method = None, ret_type = None)
    inst_9 = SootAddressDescriptor(method_5, block_idx = 3, stmt_idx = 3)
    inst_10 = SootAddressDescriptor(method_6, block_idx = 3, stmt_idx = 3)
    nose.tools.assert_equal(inst_9 > inst_10, False)


def test_less_or_equal_to():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    inst_2 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_1 <= inst_2, True)

    inst_3 = SootAddressDescriptor(method_1, block_idx = 4, stmt_idx = None)
    inst_4 = SootAddressDescriptor(method_1, block_idx = 7, stmt_idx = None)
    nose.tools.assert_equal(inst_3 <= inst_4, True)


def test_greater_or_equal_to():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method_1, block_idx = 7, stmt_idx = None)
    inst_2 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_1 >= inst_2, True)

    inst_1 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    inst_2 = SootAddressDescriptor(method_1, block_idx = 3, stmt_idx = None)
    nose.tools.assert_equal(inst_1 >= inst_2, True)


def test_add_passes():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    stmts_offset = 10
    inst_1 = SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = 12)
    nose.tools.assert_equal(SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = 2) + stmts_offset, inst_1)


@raises(TypeError)
def test_add_fails():
    method_1 = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    stmts_offset = 'xyz'
    nose.tools.assert_equal(TypeError, SootAddressDescriptor(method_1, block_idx = 2, stmt_idx = 2) + stmts_offset)


def test_copy():
    method = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method, block_idx = 2, stmt_idx = 2)
    inst_2 = SootAddressDescriptor(method, block_idx = 2, stmt_idx = 2)
    nose.tools.assert_equal(inst_1.copy(), inst_2)


def test_symbolic_soot_address_descriptor():
    method = SootMethodDescriptor(class_name='abc', name = 'abc', params = ('1', '2'), soot_method = None, ret_type = None)
    inst_1 = SootAddressDescriptor(method, block_idx = 2, stmt_idx = 2)
    nose.tools.assert_equal(inst_1.symbolic, 2 > 3)


def test_soot_address_terminator():
    assert SootAddressTerminator()


def test_soot_field_descriptor():
    assert SootFieldDescriptor(class_name = 'abc', name = 'abc', type_ = 'abc')


def test_soot_field_descriptor_repr():
    nose.tools.assert_equal(repr(SootFieldDescriptor(class_name = 'abc', name = 'abc', type_ = 'abc')), 'abc.abc')


def test_soot_field_descriptor_eq():
    inst_1 = SootFieldDescriptor(class_name = 'abc', name = 'abc', type_ = 'abc')
    inst_2 = SootFieldDescriptor(class_name = 'abc', name = 'abc', type_ = 'abc')
    nose.tools.assert_equal(inst_1.class_name, inst_2.class_name)
    nose.tools.assert_equal(inst_1.name, inst_2.name)
    nose.tools.assert_equal(inst_1.type, inst_2.type)


def test_soot_field_descriptor_ne():
    inst_1 = SootFieldDescriptor(class_name = 'abc', name = 'abc', type_ = 'abc')
    inst_2 = SootFieldDescriptor(class_name = 'pqr', name = 'abc', type_ = 'abc')
    nose.tools.assert_not_equal(inst_1, inst_2)


def test_soot_class_descriptor():
    assert SootClassDescriptor(name = 'abc', soot_class = None)


def test_soot_class_descriptor_repr():
    nose.tools.assert_equal(repr(SootClassDescriptor(name = 'abc', soot_class = None)), 'abc')


def test_soot_class_descriptor_eq():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    inst_2 = SootClassDescriptor(name = 'abc', soot_class = None)
    nose.tools.assert_equal(inst_1.name, inst_2.name)


def test_soot_class_descriptor_ne():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    inst_2 = SootClassDescriptor(name = 'pqr', soot_class = None)
    nose.tools.assert_not_equal(inst_1, inst_2)


def test_soot_class_descriptor_is_loaded():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    nose.tools.assert_equal(inst_1.is_loaded, False)
    inst_2 = SootClassDescriptor(name = 'abc', soot_class = not None)
    nose.tools.assert_equal(inst_2.is_loaded, True)


def test_soot_class_descriptor_fields():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    nose.tools.assert_equal(inst_1.fields, None)


def test_soot_class_descriptor_methods():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    nose.tools.assert_equal(inst_1.methods, None)


def test_soot_class_descriptor_superclass_name():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = None)
    nose.tools.assert_equal(inst_1.superclass_name, None)


def test_soot_class_descriptor_type():
    inst_1 = SootClassDescriptor(name = 'abc', soot_class = not None)
    nose.tools.assert_equal(inst_1.type, "java.lang.Class")


def test_soot_null_constant():
    assert SootNullConstant()


def test_soot_null_constant_repr():
    nose.tools.assert_equal(repr(SootNullConstant()), 'null')


def test_soot_null_constant_eq():
    inst_1 = SootNullConstant()
    inst_2 = SootNullConstant()
    nose.tools.assert_equal(inst_1, inst_2)


def test_soot_null_constant_ne():
    inst_1 = SootNullConstant()
    inst_2 = SootAddressTerminator()
    nose.tools.assert_not_equal(inst_1, inst_2)


def test_soot_argument():
    assert SootArgument(value = 'abc', type_ = 'pqr', is_this_ref = True)


def test_soot_argument_repr():
    nose.tools.assert_equal(repr(SootArgument(value = 'abc', type_ = 'pqr', is_this_ref = True)), 'abc (pqr)')


def test_archsoot():
    assert ArchSoot(endness=Endness.LE)


def test_archsoot_decode_type_signature():
    inst_1 = ArchSoot(endness=Endness.LE)
    nose.tools.assert_equal(inst_1.decode_type_signature('LEEEEE;'), 'EEEEE')
    nose.tools.assert_equal(inst_1.decode_type_signature('Z'), 'boolean')
    nose.tools.assert_equal(inst_1.decode_type_signature('B'), 'byte')
    nose.tools.assert_equal(inst_1.decode_type_signature('C'), 'char')
    nose.tools.assert_equal(inst_1.decode_type_signature('S'), 'short')
    nose.tools.assert_equal(inst_1.decode_type_signature('I'), 'int')
    nose.tools.assert_equal(inst_1.decode_type_signature('J'), 'long')
    nose.tools.assert_equal(inst_1.decode_type_signature('F'), 'float')
    nose.tools.assert_equal(inst_1.decode_type_signature('D'), 'double')
    nose.tools.assert_equal(inst_1.decode_type_signature('V'), 'void')


@raises(ValueError)
def test_archsoot_decode_type_signature_fails():
    inst_1 = ArchSoot(endness=Endness.LE)
    nose.tools.assert_equal(ValueError, inst_1.decode_type_signature('LAAABBB'))
    nose.tools.assert_equal(ValueError, inst_1.decode_type_signature('AAA;'))


def test_archsoot_decode_method_signature():
    inst_1 = ArchSoot(endness=Endness.LE)
    nose.tools.assert_equal(inst_1.decode_method_signature('(aaa)'), ((), None))
    nose.tools.assert_equal(inst_1.decode_method_signature('(ZZZ)'), (('boolean','boolean', 'boolean'), None))
    nose.tools.assert_equal(inst_1.decode_method_signature('(ZBCSIJFDV)'), (('boolean','byte','char','short','int','long','float','double','void'), None))
    nose.tools.assert_equal(inst_1.decode_method_signature('((B./))(Laaa;)'), (('byte','aaa'), None))


def test_archsoot_library_search_path():
    inst_1 = ArchSoot(endness=Endness.LE)
    nose.tools.assert_equal(inst_1.library_search_path(pedantic = False), [])
