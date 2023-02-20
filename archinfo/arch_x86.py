from .arch import Arch, register_arch, Endness, Register
from .tls import TLSArchInfo
from .archerror import ArchError

_NATIVE_FUNCTION_PROLOGS = [
    rb"\x8b\xff\x55\x8b\xec",  # mov edi, edi; push ebp; mov ebp, esp
    rb"\x55\x8b\xec",  # push ebp; mov ebp, esp
    rb"\x55\x89\xe5",  # push ebp; mov ebp, esp
    rb"\x55\x57\x56",  # push ebp; push edi; push esi
    # mov eax, 0x000000??; (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) sub esp
    rb"\xb8[\x00-\xff]\x00\x00\x00[\x50\x51\x52\x53\x55\x56\x57]{0,7}\x8b[\x00-\xff]{2}",
    # (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) sub esp
    rb"[\x50\x51\x52\x53\x55\x56\x57]{1,7}\x83\xec[\x00-\xff]{2,4}",
    # (push ebp; push eax; push edi; push ebx; push esi; push edx; push ecx) mov xxx, xxx
    rb"[\x50\x51\x52\x53\x55\x56\x57]{1,7}\x8b[\x00-\xff]{2}",
    rb"(\x81|\x83)\xec",  # sub xxx %esp
]
# every function prolog can potentially be prefixed with endbr32
_endbr32 = b"\xf3\x0f\x1e\xfb"
_prefixed = [(_endbr32 + prolog) for prolog in _NATIVE_FUNCTION_PROLOGS]
_FUNCTION_PROLOGS = _prefixed + _NATIVE_FUNCTION_PROLOGS


class ArchX86(Arch):
    def __init__(self, endness=Endness.LE):
        if endness != Endness.LE:
            raise ArchError("Arch i386 must be little endian")
        super().__init__(endness)

    bits = 32
    name = "X86"
    qemu_name = "i386"
    ida_processor = "metapc"
    linux_name = "i386"
    triplet = "i386-linux-gnu"
    max_inst_bytes = 15
    call_sp_fix = -4
    call_pushes_ret = True
    stack_change = -4
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {"short": 16, "int": 32, "long": 32, "long long": 64}
    function_prologs = _FUNCTION_PROLOGS
    function_epilogs = {
        rb"\xc9\xc3",  # leave; ret
        rb"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3",  # pop <reg>; ret
        rb"[^\x48][\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3",  #  add esp, <siz>; retq
    }
    ret_instruction = b"\xc3"
    nop_instruction = b"\x90"
    instruction_alignment = 1
    register_list = [
        Register(
            name="eax",
            size=4,
            subregisters=[("ax", 0, 2), ("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value=0x1C,
        ),
        Register(
            name="ecx",
            size=4,
            subregisters=[("cx", 0, 2), ("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="edx",
            size=4,
            subregisters=[("dx", 0, 2), ("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="ld_destructor",
        ),
        Register(
            name="ebx",
            size=4,
            subregisters=[("bx", 0, 2), ("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="esp",
            size=4,
            alias_names=("sp",),
            general_purpose=True,
            default_value=(Arch.initial_sp, True, "global"),
        ),
        Register(name="ebp", size=4, alias_names=("bp",), general_purpose=True, argument=True, linux_entry_value=0),
        Register(
            name="esi",
            size=4,
            subregisters=[("si", 0, 2), ("sil", 0, 1), ("sih", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="edi",
            size=4,
            subregisters=[("di", 0, 2), ("dil", 0, 1), ("dih", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(name="d", size=4, alias_names=("dflag",), default_value=(1, False, None), concrete=False),
        Register(name="id", size=4, alias_names=("idflag",), default_value=(1, False, None), concrete=False),
        Register(name="ac", size=4, alias_names=("acflag",), default_value=(0, False, None), concrete=False),
        Register(name="eip", size=4, alias_names=("ip", "pc")),
        Register(
            name="fpreg",
            size=64,
            subregisters=[
                ("mm0", 0, 8),
                ("mm1", 8, 8),
                ("mm2", 16, 8),
                ("mm3", 24, 8),
                ("mm4", 32, 8),
                ("mm5", 40, 8),
                ("mm6", 48, 8),
                ("mm7", 56, 8),
            ],
            alias_names=("fpu_regs",),
            floating_point=True,
            concrete=False,
        ),
        Register(name="fptag", size=8, alias_names=("fpu_tags",), floating_point=True, default_value=(0, False, None)),
        Register(name="fpround", size=4, floating_point=True, default_value=(0, False, None)),
        Register(name="fc3210", size=4, floating_point=True),
        Register(name="ftop", size=4, floating_point=True, default_value=(7, False, None), artificial=True),
        Register(name="sseround", size=4, vector=True, default_value=(0, False, None)),
        Register(name="xmm0", size=16, vector=True),
        Register(name="xmm1", size=16, vector=True),
        Register(name="xmm2", size=16, vector=True),
        Register(name="xmm3", size=16, vector=True),
        Register(name="xmm4", size=16, vector=True),
        Register(name="xmm5", size=16, vector=True),
        Register(name="xmm6", size=16, vector=True),
        Register(name="xmm7", size=16, vector=True),
        Register(name="cs", size=2),
        Register(name="ds", size=2),
        Register(name="es", size=2),
        Register(name="fs", size=2, default_value=(0, False, None), concrete=False),
        Register(name="gs", size=2, default_value=(0, False, None), concrete=False),
        Register(name="ss", size=2),
        Register(name="ldt", size=8, default_value=(0, False, None), concrete=False),
        Register(name="gdt", size=8, default_value=(0, False, None), concrete=False),
        Register(name="cmstart", size=4),
        Register(name="cmlen", size=4),
        Register(name="nraddr", size=4),
        Register(name="sc_class", size=4),
    ]

    symbol_type_translation = {10: "STT_GNU_IFUNC", "STT_LOOS": "STT_GNU_IFUNC"}
    lib_paths = ["/lib32", "/usr/lib32"]
    got_section_name = ".got.plt"
    ld_linux_name = "ld-linux.so.2"
    elf_tls = TLSArchInfo(2, 56, [8], [4], [0], 0, 0)


register_arch([r".*i?\d86|.*x32|.*x86|.*metapc"], 32, Endness.LE, ArchX86)
