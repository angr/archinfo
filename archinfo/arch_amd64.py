from .arch import Arch, register_arch, Endness, Register
from .tls import TLSArchInfo
from .archerror import ArchError

_NATIVE_FUNCTION_PROLOGS = [
    rb"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    rb"\x48[\x83,\x81]\xec[\x00-\xff]",  # sub rsp, xxx
]
# every function prolog can potentially be prefixed with endbr64
_endbr64 = b"\xf3\x0f\x1e\xfa"
_prefixed = [(_endbr64 + prolog) for prolog in _NATIVE_FUNCTION_PROLOGS]
_FUNCTION_PROLOGS = _prefixed + _NATIVE_FUNCTION_PROLOGS


class ArchAMD64(Arch):
    def __init__(self, endness=Endness.LE):
        if endness != Endness.LE:
            raise ArchError("Arch AMD64 must be little endian")
        super().__init__(endness)

    bits = 64
    vex_endness = "VexEndnessLE"
    name = "AMD64"
    qemu_name = "x86_64"
    ida_processor = "metapc"
    linux_name = "x86_64"
    triplet = "x86_64-linux-gnu"
    max_inst_bytes = 15
    vex_conditional_helpers = True
    call_pushes_ret = True
    stack_change = -8
    initial_sp = 0x7FFFFFFFFFF0000
    call_sp_fix = -8
    memory_endness = Endness.LE
    register_endness = Endness.LE
    sizeof = {"short": 16, "int": 32, "long": 64, "long long": 64}
    function_prologs = _FUNCTION_PROLOGS
    function_epilogs = {
        rb"\xc9\xc3",  # leaveq; retq
        rb"([^\x41][\x50-\x5f]{1}|\x41[\x50-\x5f])\xc3",  # pop <reg>; retq
        rb"\x48[\x83,\x81]\xc4([\x00-\xff]{1}|[\x00-\xff]{4})\xc3",  #  add rsp, <siz>; retq
    }
    ret_instruction = b"\xc3"
    nop_instruction = b"\x90"
    instruction_alignment = 1
    register_list = [
        Register(
            name="rax",
            size=8,
            subregisters=[("eax", 0, 4), ("ax", 0, 2), ("al", 0, 1), ("ah", 1, 1)],
            general_purpose=True,
            linux_entry_value=0x1C,
        ),
        Register(
            name="rcx",
            size=8,
            subregisters=[("ecx", 0, 4), ("cx", 0, 2), ("cl", 0, 1), ("ch", 1, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="rdx",
            size=8,
            subregisters=[("edx", 0, 4), ("dx", 0, 2), ("dl", 0, 1), ("dh", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="ld_destructor",
        ),
        Register(
            name="rbx",
            size=8,
            subregisters=[("ebx", 0, 4), ("bx", 0, 2), ("bl", 0, 1), ("bh", 1, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="rsp",
            size=8,
            subregisters=[("esp", 0, 4)],
            alias_names=("sp",),
            general_purpose=True,
            default_value=(initial_sp, True, "global"),
        ),
        Register(
            name="rbp",
            size=8,
            subregisters=[("ebp", 0, 4), ("_bp", 0, 2), ("bpl", 0, 1), ("bph", 1, 1)],
            alias_names=("bp",),
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="rsi",
            size=8,
            subregisters=[("esi", 0, 4), ("si", 0, 2), ("sil", 0, 1), ("sih", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="argv",
        ),
        Register(
            name="rdi",
            size=8,
            subregisters=[("edi", 0, 4), ("di", 0, 2), ("dil", 0, 1), ("dih", 1, 1)],
            general_purpose=True,
            argument=True,
            linux_entry_value="argc",
        ),
        Register(
            name="r8",
            size=8,
            subregisters=[("r8d", 0, 4), ("r8w", 0, 2), ("r8b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r9",
            size=8,
            subregisters=[("r9d", 0, 4), ("r9w", 0, 2), ("r9b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r10",
            size=8,
            subregisters=[("r10d", 0, 4), ("r10w", 0, 2), ("r10b", 0, 1)],
            general_purpose=True,
            argument=True,
        ),
        Register(
            name="r11", size=8, subregisters=[("r11d", 0, 4), ("r11w", 0, 2), ("r11b", 0, 1)], general_purpose=True
        ),
        Register(
            name="r12",
            size=8,
            subregisters=[("r12d", 0, 4), ("r12w", 0, 2), ("r12b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r13",
            size=8,
            subregisters=[("r13d", 0, 4), ("r13w", 0, 2), ("r13b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r14",
            size=8,
            subregisters=[("r14d", 0, 4), ("r14w", 0, 2), ("r14b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(
            name="r15",
            size=8,
            subregisters=[("r15d", 0, 4), ("r15w", 0, 2), ("r15b", 0, 1)],
            general_purpose=True,
            linux_entry_value=0,
        ),
        Register(name="d", size=8, alias_names=("dflag",), default_value=(1, False, None), concrete=False),
        Register(name="rip", size=8, alias_names=("ip", "pc"), general_purpose=True),
        Register(name="ac", size=8, alias_names=("acflag",), concrete=False),
        Register(name="id", size=8, alias_names=("idflag",)),
        Register(
            name="fs",
            size=8,
            alias_names=("fs_const",),
            default_value=(0x9000000000000000, True, "global"),
            concrete=False,
        ),
        Register(name="sseround", size=8, vector=True, default_value=(0, False, None)),
        Register(name="cr0", size=8),
        Register(name="cr2", size=8),
        Register(name="cr3", size=8),
        Register(name="cr4", size=8),
        Register(name="cr8", size=8),
        Register(
            name="ymm0",
            size=32,
            subregisters=[("xmm0", 0, 16), ("xmm0lq", 0, 8), ("xmm0hq", 8, 8), ("ymm0hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm1",
            size=32,
            subregisters=[("xmm1", 0, 16), ("xmm1lq", 0, 8), ("xmm1hq", 8, 8), ("ymm1hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm2",
            size=32,
            subregisters=[("xmm2", 0, 16), ("xmm2lq", 0, 8), ("xmm2hq", 8, 8), ("ymm2hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm3",
            size=32,
            subregisters=[("xmm3", 0, 16), ("xmm3lq", 0, 8), ("xmm3hq", 8, 8), ("ymm3hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm4",
            size=32,
            subregisters=[("xmm4", 0, 16), ("xmm4lq", 0, 8), ("xmm4hq", 8, 8), ("ymm4hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm5",
            size=32,
            subregisters=[("xmm5", 0, 16), ("xmm5lq", 0, 8), ("xmm5hq", 8, 8), ("ymm5hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm6",
            size=32,
            subregisters=[("xmm6", 0, 16), ("xmm6lq", 0, 8), ("xmm6hq", 8, 8), ("ymm6hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm7",
            size=32,
            subregisters=[("xmm7", 0, 16), ("xmm7lq", 0, 8), ("xmm7hq", 8, 8), ("ymm7hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm8",
            size=32,
            subregisters=[("xmm8", 0, 16), ("xmm8lq", 0, 8), ("xmm8hq", 8, 8), ("ymm8hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm9",
            size=32,
            subregisters=[("xmm9", 0, 16), ("xmm9lq", 0, 8), ("xmm9hq", 8, 8), ("ymm9hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm10",
            size=32,
            subregisters=[("xmm10", 0, 16), ("xmm10lq", 0, 8), ("xmm10hq", 8, 8), ("ymm10hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm11",
            size=32,
            subregisters=[("xmm11", 0, 16), ("xmm11lq", 0, 8), ("xmm11hq", 8, 8), ("ymm11hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm12",
            size=32,
            subregisters=[("xmm12", 0, 16), ("xmm12lq", 0, 8), ("xmm12hq", 8, 8), ("ymm12hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm13",
            size=32,
            subregisters=[("xmm13", 0, 16), ("xmm13lq", 0, 8), ("xmm13hq", 8, 8), ("ymm13hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm14",
            size=32,
            subregisters=[("xmm14", 0, 16), ("xmm14lq", 0, 8), ("xmm14hq", 8, 8), ("ymm14hx", 16, 16)],
            vector=True,
        ),
        Register(
            name="ymm15",
            size=32,
            subregisters=[("xmm15", 0, 16), ("xmm15lq", 0, 8), ("xmm15hq", 8, 8), ("ymm15hx", 16, 16)],
            vector=True,
        ),
        Register(name="ftop", size=4, floating_point=True, default_value=(7, False, None), artificial=True),
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
        ),
        Register(name="fptag", size=8, alias_names=("fpu_tags",), floating_point=True, default_value=(0, False, None)),
        Register(name="fpround", size=8, floating_point=True, default_value=(0, False, None)),
        Register(name="fc3210", size=8, floating_point=True),
        Register(name="cmstart", size=8),
        Register(name="cmlen", size=8),
        Register(name="nraddr", size=8),
        Register(name="gs", size=8, alias_names=("gs_const",), concrete=False),
        Register(name="cs_seg", size=2),
        Register(name="ds_seg", size=2),
        Register(name="es_seg", size=2),
        Register(name="fs_seg", size=2),
        Register(name="fs_seg", size=2),
        Register(name="ss_seg", size=2),
    ]

    symbol_type_translation = {10: "STT_GNU_IFUNC", "STT_LOOS": "STT_GNU_IFUNC"}
    got_section_name = ".got.plt"
    ld_linux_name = "ld-linux-x86-64.so.2"
    elf_tls = TLSArchInfo(2, 704, [16], [8], [0], 0, 0)


register_arch([r".*amd64|.*x64|.*x86_64|.*metapc"], 64, Endness.LE, ArchAMD64)
