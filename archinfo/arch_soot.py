
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
        return isinstance(other, SootAddressDescriptor) and \
                self.method == other.method and \
                self.block_idx == other.block_idx and \
                self.stmt_idx == other.stmt_idx

    def copy(self):
        return SootAddressDescriptor(method=self.method,
                                     block_idx=self.block_idx,
                                     stmt_idx=self.stmt_idx
                                     )

    @property
    def symbolic(self):
        return False


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


register_arch(['soot'], 8, Endness.BE, ArchSoot)
