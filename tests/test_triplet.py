# pylint:disable=no-self-use
from __future__ import annotations

import unittest

import archinfo
from archinfo.arch import Endness, all_arches

# Arch.triplet is substituted into the directory names library_search_path builds, and cle
# searches those for a target's shared libraries, so it has to be the multiarch tuple for the
# architecture reporting it. Seven pairs are left unpinned. ArchAArch64, ArchARM and
# ArchARMHF at big-endian, ArchPPC32 at little-endian and ArchRISCV64 at big-endian each
# report the tuple of the opposite endness, and ArchARMCortexM at either endness reports
# arm-none-eabi, a bare-metal triplet rather than a multiarch tuple. What those should
# report instead is a wider question than this file settles.
EXPECTED = {
    ("ArchAArch64", Endness.LE): "aarch64-linux-gnu",
    ("ArchAMD64", Endness.LE): "x86_64-linux-gnu",
    ("ArchARMEL", Endness.LE): "arm-linux-gnueabi",
    ("ArchARMHF", Endness.LE): "arm-linux-gnueabihf",
    ("ArchMIPS32", Endness.BE): "mips-linux-gnu",
    ("ArchMIPS32", Endness.LE): "mipsel-linux-gnu",
    ("ArchMIPS64", Endness.BE): "mips64-linux-gnuabi64",
    ("ArchMIPS64", Endness.LE): "mips64el-linux-gnuabi64",
    ("ArchMIPSN32", Endness.BE): "mips64-linux-gnuabin32",
    ("ArchMIPSN32", Endness.LE): "mips64el-linux-gnuabin32",
    ("ArchPPC32", Endness.BE): "powerpc-linux-gnu",
    ("ArchPPC64", Endness.BE): "powerpc64-linux-gnu",
    ("ArchPPC64", Endness.LE): "powerpc64le-linux-gnu",
    ("ArchRISCV64", Endness.LE): "riscv64-linux-gnu",
    ("ArchS390X", Endness.BE): "s390x-linux-gnu",
    ("ArchX86", Endness.LE): "i386-linux-gnu",
}


class TestTriplet(unittest.TestCase):
    """
    The triplet is a multiarch directory name, so it has to name the bit width, the byte order
    and the ABI of the architecture reporting it.
    """

    def test_triplets(self):
        for (name, endness), expected in EXPECTED.items():
            arch = getattr(archinfo, name)(endness)
            assert arch.triplet == expected, name

    def test_gnueabihf_belongs_to_32_bit_arm(self):
        # aarch64 carried arm's hard-float EABI suffix, which is where this test comes from.
        for arch in all_arches:
            if arch.triplet and "eabi" in arch.triplet:
                assert arch.bits == 32, arch.name

    def test_the_triplet_names_the_directory_cle_searches(self):
        for (name, endness), expected in EXPECTED.items():
            arch = getattr(archinfo, name)(endness)
            assert f"/lib/{expected}/" in arch.library_search_path(), name
