# pylint:disable=missing-class-docstring,no-self-use
import re
import unittest

from archinfo import ArchX86, Endness, all_arches, arch_from_id, register_arch
from archinfo.arch import _all_arches_set, arch_id_map


class ArchThrowaway(ArchX86):
    def __init__(self, endness=Endness.LE):
        super().__init__(endness)
        self.name = "THROWAWAY"


class TestRegisterArch(unittest.TestCase):
    def setUp(self):
        self._id_map = list(arch_id_map)
        self._all_arches = list(all_arches)
        self._arch_set = set(_all_arches_set)

    def tearDown(self):
        arch_id_map[:] = self._id_map
        all_arches[:] = self._all_arches
        _all_arches_set.clear()
        _all_arches_set.update(self._arch_set)

    def test_register_arch_accepts_a_compiled_regex(self):
        # register_arch documents "str or compiled regular expression", and the check for the second
        # kind read re._pattern_type, which Python dropped in 3.7, so a compiled pattern raised
        # AttributeError instead of registering.
        register_arch([re.compile("^throwaway$")], 32, Endness.LE, ArchThrowaway)
        assert isinstance(arch_from_id("throwaway"), ArchThrowaway)

    def test_register_arch_still_rejects_other_types(self):
        not_a_regex: list = [42]
        with self.assertRaises(TypeError):
            register_arch(not_a_regex, 32, Endness.LE, ArchThrowaway)


if __name__ == "__main__":
    unittest.main()
