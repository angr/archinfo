
from .arch import Arch, register_arch, Endness


class SootMethodDescriptor(object):
    def __init__(self, class_name, name, params):
        self.class_name = class_name
        self.name = name
        self.params = params

    def __repr__(self):
        return "%s.%s(%s)" % (self.class_name, self.name, ",".join(self.params))

    def __hash__(self):
        return hash((self.class_name, self.name, self.params))

    def __eq__(self, other):
        return isinstance(other, SootMethodDescriptor) and \
                self.class_name == other.class_name and \
                self.name == other.name and \
                self.params == other.params

    def __ne__(self, other):
        return not self == other

    @classmethod
    def from_string(cls, tstr):
        # this should be the opposite of repr
        tstr = tstr.strip()
        class_and_method, tparams = tstr.split("(")
        params_str = tparams.split(")")[0]
        if params_str == "":
            params = tuple()
        else:
            params = tuple([t.strip() for t in params_str.split(",")])
        class_name, _, method = class_and_method.rpartition(".")
        return cls(class_name, method, params)

    @property
    def fullname(self):
        return "%s.%s" % (self.class_name, self.name)

    @classmethod
    def from_method(cls, method):
        return cls(method.class_name, method.name, method.params)

    @property
    def symbolic(self):
        return False


class SootAddressDescriptor(object):
    def __init__(self, method, block_idx, stmt_idx):

        if not isinstance(method, SootMethodDescriptor):
            raise ValueError('The parameter "method" must be an instance of SootMethodDescriptor.')

        self.method = method
        self.block_idx = block_idx
        self.stmt_idx = stmt_idx

    def __repr__(self):
        return "<%s+(%s:%s)>" % (repr(self.method),
                               self.block_idx,
                               '%d' % self.stmt_idx if self.stmt_idx is not None else '[0]'
                               )

    def __hash__(self):
        return hash((self.method, self.stmt_idx))

    def __eq__(self, other):
        # We do not compare the block IDs since statement IDs are unique enough
        return isinstance(other, SootAddressDescriptor) and \
                self.method == other.method and \
                self.stmt_idx == other.stmt_idx

    def __ne__(self, other):
        return not self == other

    def __lt__(self, other):
        if not isinstance(other, SootAddressDescriptor):
            raise TypeError("You cannot compare a SootAddressDescriptor with a %s." % type(other))

        if self.method != other.method:
            raise ValueError("You cannot compare two SootAddressDescriptor instances of two different methods.")

        return self.stmt_idx < other.stmt_idx

    def __le__(self, other):
        if not isinstance(other, SootAddressDescriptor):
            raise TypeError("You cannot compare a SootAddressDescriptor with a %s." % type(other))

        if self.method != other.method:
            raise ValueError("You cannot compare two SootAddressDescriptor instances of two different methods.")

        return self.stmt_idx <= other.stmt_idx

    def copy(self):
        return SootAddressDescriptor(method=self.method,
                                     block_idx=self.block_idx,
                                     stmt_idx=self.stmt_idx
                                     )

    @property
    def symbolic(self):
        return False

    def __add__(self, stmts_offset):

        if not isinstance(stmts_offset, (int, long)):
            raise TypeError('The stmts_offset must be an int or a long.')

        s = self.copy()
        s.stmt_idx += stmts_offset
        return s


class SootAddressTerminator(SootAddressDescriptor):
    def __init__(self):
        super(SootAddressTerminator, self).__init__(SootMethodDescriptor("dummy", "dummy", tuple()), 0, 0)

    def __repr__(self):
        return "<Terminator>"


class ArchSoot(Arch):
    def __init__(self, endness=Endness.BE):  # pylint:disable=unused-args

        assert endness == Endness.BE

        super(ArchSoot, self).__init__(Endness.BE)

    vex_arch = None  # No VEX support
    qemu_name = None  # No Qemu/Unicorn-engine support
    bits = 64
    address_types = (SootAddressDescriptor, )
    function_address_types = (SootMethodDescriptor, )

    name = 'Soot'

    def library_search_path(self, pedantic=False):
        # system specific paths cannot get determinend,
        # since java is mostly system independent
        # => return an empty list
        return []

register_arch(['soot'], 8, Endness.BE, ArchSoot)
