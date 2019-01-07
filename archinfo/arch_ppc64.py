import logging

l = logging.getLogger("archinfo.arch_ppc64")

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

try:
    import keystone as _keystone
except ImportError:
    _keystone = None

#try:
#    import unicorn as _unicorn
#except ImportError:
#    _unicorn = None

try:
    import pyvex as _pyvex
except ImportError:
    _pyvex = None

from .arch import Arch, register_arch, Endness, Register
from .tls import TLSArchInfo

# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
# Normally r1 is used as stack pointer

class ArchPPC64(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchPPC64, self).__init__(endness)
        if endness == Endness.BE:
            self.function_prologs = {
                br"\x94\x21[\x00-\xff]{2}\x7c\x08\x02\xa6",                        # stwu r1, -off(r1); mflr r0
                br"(?!\x94\x21[\x00-\xff]{2})\x7c\x08\x02\xa6",                    # mflr r0
                br"\xf8\x61[\x00-\xff]{2}",                                        # std r3, -off(r1)
            }
            self.function_epilogs = {
                br"[\x00-\xff]{2}\x03\xa6([\x00-\xff]{4}){0,6}\x4e\x80\x00\x20"    # mtlr reg; ... ; blr
            }
            self.triplet = 'powerpc-linux-gnu'
        self.argument_register_positions = {
            self.registers['r3'][0]: 0,
            self.registers['r4'][0]: 1,
            self.registers['r5'][0]: 2,
            self.registers['r6'][0]: 3,
            self.registers['r7'][0]: 4,
            self.registers['r8'][0]: 5,
            self.registers['r9'][0]: 6,
            self.registers['r10'][0]: 7,
            # fp registers
            self.registers['vsr1'][0]: 0,
            self.registers['vsr2'][0]: 1,
            self.registers['vsr3'][0]: 2,
            self.registers['vsr4'][0]: 3,
            self.registers['vsr5'][0]: 4,
            self.registers['vsr6'][0]: 5,
            self.registers['vsr7'][0]: 6,
            self.registers['vsr8'][0]: 7,
            self.registers['vsr9'][0]: 8,
            self.registers['vsr10'][0]: 9,
            self.registers['vsr11'][0]: 10,
            self.registers['vsr12'][0]: 11,
            self.registers['vsr13'][0]: 12,
            # vector registers
            self.registers['vsr2'][0]: 0,
            self.registers['vsr3'][0]: 1,
            self.registers['vsr4'][0]: 2,
            self.registers['vsr5'][0]: 3,
            self.registers['vsr6'][0]: 4,
            self.registers['vsr7'][0]: 5,
            self.registers['vsr8'][0]: 6,
            self.registers['vsr9'][0]: 7,
            self.registers['vsr10'][0]: 8,
            self.registers['vsr11'][0]: 9,
            self.registers['vsr12'][0]: 10,
            self.registers['vsr13'][0]: 11,
        } if _pyvex is not None else None

    bits = 64
    vex_arch = "VexArchPPC64"
    name = "PPC64"
    qemu_name = 'ppc64'
    ida_processor = 'ppc64'
    triplet = 'powerpc64le-linux-gnu'
    linux_name = 'ppc750'
    max_inst_bytes = 4
    ret_offset = 40
    syscall_num_offset = 16
    call_pushes_ret = False
    stack_change = -8
    initial_sp = 0xffffffffff000000
    sizeof = {'short': 16, 'int': 32, 'long': 64, 'long long': 64}
    if _capstone:
        cs_arch = _capstone.CS_ARCH_PPC
        cs_mode = _capstone.CS_MODE_64 + _capstone.CS_MODE_LITTLE_ENDIAN
    if _keystone:
        ks_arch = _keystone.KS_ARCH_PPC
        ks_mode = _keystone.KS_MODE_64 + _keystone.KS_MODE_LITTLE_ENDIAN
    # Unicorn not supported
    #uc_arch = _unicorn.UC_ARCH_PPC if _unicorn else None
    #uc_mode = (_unicorn.UC_MODE_64 + _unicorn.UC_MODE_LITTLE_ENDIAN) if _unicorn else None
    ret_instruction = b"\x20\x00\x80\x4e"
    nop_instruction = b"\x00\x00\x00\x60"
    instruction_alignment = 4
    register_list = [
        Register(name='gpr0', size=8, alias_names=('r0',),
                 general_purpose=True),
        Register(name='gpr1', size=8, alias_names=('r1', 'sp'),
                 general_purpose=True, default_value=(initial_sp, True, 'global')),
        Register(name='gpr2', size=8, alias_names=('r2', 'rtoc'),
                 general_purpose=True, persistent=True, linux_entry_value='toc'),
        Register(name='gpr3', size=8, alias_names=('r3',),
                 general_purpose=True, argument=True, linux_entry_value='argc'),
        Register(name='gpr4', size=8, alias_names=('r4',),
                 general_purpose=True, argument=True, linux_entry_value='argv'),
        Register(name='gpr5', size=8, alias_names=('r5',),
                 general_purpose=True, argument=True, linux_entry_value='envp'),
        Register(name='gpr6', size=8, alias_names=('r6',),
                 general_purpose=True, argument=True, linux_entry_value='auxv'),
        Register(name='gpr7', size=8, alias_names=('r7',),
                 general_purpose=True, argument=True, linux_entry_value='ld_destructor'),
        Register(name='gpr8', size=8, alias_names=('r8',),
                 general_purpose=True, argument=True),
        Register(name='gpr9', size=8, alias_names=('r9',),
                 general_purpose=True, argument=True),
        Register(name='gpr10', size=8, alias_names=('r10',),
                 general_purpose=True, argument=True),
        Register(name='gpr11', size=8, alias_names=('r11',),
                 general_purpose=True),
        Register(name='gpr12', size=8, alias_names=('r12',),
                 general_purpose=True),
        Register(name='gpr13', size=8, alias_names=('r13',),
                 general_purpose=True),
        Register(name='gpr14', size=8, alias_names=('r14',),
                 general_purpose=True),
        Register(name='gpr15', size=8, alias_names=('r15',),
                 general_purpose=True),
        Register(name='gpr16', size=8, alias_names=('r16',),
                 general_purpose=True),
        Register(name='gpr17', size=8, alias_names=('r17',),
                 general_purpose=True),
        Register(name='gpr18', size=8, alias_names=('r18',),
                 general_purpose=True),
        Register(name='gpr19', size=8, alias_names=('r19',),
                 general_purpose=True),
        Register(name='gpr20', size=8, alias_names=('r20',),
                 general_purpose=True),
        Register(name='gpr21', size=8, alias_names=('r21',),
                 general_purpose=True),
        Register(name='gpr22', size=8, alias_names=('r22',),
                 general_purpose=True),
        Register(name='gpr23', size=8, alias_names=('r23',),
                 general_purpose=True),
        Register(name='gpr24', size=8, alias_names=('r24',),
                 general_purpose=True),
        Register(name='gpr25', size=8, alias_names=('r25',),
                 general_purpose=True, persistent=True),
        Register(name='gpr26', size=8, alias_names=('r26',),
                 general_purpose=True),
        Register(name='gpr27', size=8, alias_names=('r27',),
                 general_purpose=True),
        Register(name='gpr28', size=8, alias_names=('r28',),
                 general_purpose=True),
        Register(name='gpr29', size=8, alias_names=('r29',),
                 general_purpose=True),
        Register(name='gpr30', size=8, alias_names=('r30',),
                 general_purpose=True),
        Register(name='gpr31', size=8, alias_names=('r31', 'bp'),
                 general_purpose=True),
        Register(name='vsr0', size=16,  subregisters=[('fpr0', 0, 8)],
                 alias_names=('v0',), floating_point=True),
        Register(name='vsr1', size=16,  subregisters=[('fpr1', 0, 8)],
                 alias_names=('v1',), floating_point=True),
        Register(name='vsr2', size=16,  subregisters=[('fpr2', 0, 8)],
                 alias_names=('v2',), floating_point=True),
        Register(name='vsr3', size=16,  subregisters=[('fpr3', 0, 8)],
                 alias_names=('v3',), floating_point=True),
        Register(name='vsr4', size=16,  subregisters=[('fpr4', 0, 8)],
                 alias_names=('v4',), floating_point=True),
        Register(name='vsr5', size=16,  subregisters=[('fpr5', 0, 8)],
                 alias_names=('v5',), floating_point=True),
        Register(name='vsr6', size=16,  subregisters=[('fpr6', 0, 8)],
                 alias_names=('v6',), floating_point=True),
        Register(name='vsr7', size=16,  subregisters=[('fpr7', 0, 8)],
                 alias_names=('v7',), floating_point=True),
        Register(name='vsr8', size=16,  subregisters=[('fpr8', 0, 8)],
                 alias_names=('v8',), floating_point=True),
        Register(name='vsr9', size=16,  subregisters=[('fpr9', 0, 8)],
                 alias_names=('v9',), floating_point=True),
        Register(name='vsr10', size=16, subregisters=[('fpr10', 0, 8)],
                 alias_names=('v10',), floating_point=True),
        Register(name='vsr11', size=16, subregisters=[('fpr11', 0, 8)],
                 alias_names=('v11',), floating_point=True),
        Register(name='vsr12', size=16, subregisters=[('fpr12', 0, 8)],
                 alias_names=('v12',), floating_point=True),
        Register(name='vsr13', size=16, subregisters=[('fpr13', 0, 8)],
                 alias_names=('v13',), floating_point=True),
        Register(name='vsr14', size=16, subregisters=[('fpr14', 0, 8)],
                 alias_names=('v14',), floating_point=True),
        Register(name='vsr15', size=16, subregisters=[('fpr15', 0, 8)],
                 alias_names=('v15',), floating_point=True),
        Register(name='vsr16', size=16, subregisters=[('fpr16', 0, 8)],
                 alias_names=('v16',), floating_point=True),
        Register(name='vsr17', size=16, subregisters=[('fpr17', 0, 8)],
                 alias_names=('v17',), floating_point=True),
        Register(name='vsr18', size=16, subregisters=[('fpr18', 0, 8)],
                 alias_names=('v18',), floating_point=True),
        Register(name='vsr19', size=16, subregisters=[('fpr19', 0, 8)],
                 alias_names=('v19',), floating_point=True),
        Register(name='vsr20', size=16, subregisters=[('fpr20', 0, 8)],
                 alias_names=('v20',), floating_point=True),
        Register(name='vsr21', size=16, subregisters=[('fpr21', 0, 8)],
                 alias_names=('v21',), floating_point=True),
        Register(name='vsr22', size=16, subregisters=[('fpr22', 0, 8)],
                 alias_names=('v22',), floating_point=True),
        Register(name='vsr23', size=16, subregisters=[('fpr23', 0, 8)],
                 alias_names=('v23',), floating_point=True),
        Register(name='vsr24', size=16, subregisters=[('fpr24', 0, 8)],
                 alias_names=('v24',), floating_point=True),
        Register(name='vsr25', size=16, subregisters=[('fpr25', 0, 8)],
                 alias_names=('v25',), floating_point=True),
        Register(name='vsr26', size=16, subregisters=[('fpr26', 0, 8)],
                 alias_names=('v26',), floating_point=True),
        Register(name='vsr27', size=16, subregisters=[('fpr27', 0, 8)],
                 alias_names=('v27',), floating_point=True),
        Register(name='vsr28', size=16, subregisters=[('fpr28', 0, 8)],
                 alias_names=('v28',), floating_point=True),
        Register(name='vsr29', size=16, subregisters=[('fpr29', 0, 8)],
                 alias_names=('v29',), floating_point=True),
        Register(name='vsr30', size=16, subregisters=[('fpr30', 0, 8)],
                 alias_names=('v30',), floating_point=True),
        Register(name='vsr31', size=16, subregisters=[('fpr31', 0, 8)],
                 alias_names=('v31',), floating_point=True),
        Register(name='vsr32', size=16, alias_names=('v32',), vector=True),
        Register(name='vsr33', size=16, alias_names=('v33',), vector=True),
        Register(name='vsr34', size=16, alias_names=('v34',), vector=True),
        Register(name='vsr35', size=16, alias_names=('v35',), vector=True),
        Register(name='vsr36', size=16, alias_names=('v36',), vector=True),
        Register(name='vsr37', size=16, alias_names=('v37',), vector=True),
        Register(name='vsr38', size=16, alias_names=('v38',), vector=True),
        Register(name='vsr39', size=16, alias_names=('v39',), vector=True),
        Register(name='vsr40', size=16, alias_names=('v40',), vector=True),
        Register(name='vsr41', size=16, alias_names=('v41',), vector=True),
        Register(name='vsr42', size=16, alias_names=('v42',), vector=True),
        Register(name='vsr43', size=16, alias_names=('v43',), vector=True),
        Register(name='vsr44', size=16, alias_names=('v44',), vector=True),
        Register(name='vsr45', size=16, alias_names=('v45',), vector=True),
        Register(name='vsr46', size=16, alias_names=('v46',), vector=True),
        Register(name='vsr47', size=16, alias_names=('v47',), vector=True),
        Register(name='vsr48', size=16, alias_names=('v48',), vector=True),
        Register(name='vsr49', size=16, alias_names=('v49',), vector=True),
        Register(name='vsr50', size=16, alias_names=('v50',), vector=True),
        Register(name='vsr51', size=16, alias_names=('v51',), vector=True),
        Register(name='vsr52', size=16, alias_names=('v52',), vector=True),
        Register(name='vsr53', size=16, alias_names=('v53',), vector=True),
        Register(name='vsr54', size=16, alias_names=('v54',), vector=True),
        Register(name='vsr55', size=16, alias_names=('v55',), vector=True),
        Register(name='vsr56', size=16, alias_names=('v56',), vector=True),
        Register(name='vsr57', size=16, alias_names=('v57',), vector=True),
        Register(name='vsr58', size=16, alias_names=('v58',), vector=True),
        Register(name='vsr59', size=16, alias_names=('v59',), vector=True),
        Register(name='vsr60', size=16, alias_names=('v60',), vector=True),
        Register(name='vsr61', size=16, alias_names=('v61',), vector=True),
        Register(name='vsr62', size=16, alias_names=('v62',), vector=True),
        Register(name='vsr63', size=16, alias_names=('v63',), vector=True),
        Register(name='cia', size=8, alias_names=('ip', 'pc')),
        Register(name='lr', size=8),
        Register(name='ctr', size=8),
        Register(name='xer_so', size=1),
        Register(name='xer_ov', size=1),
        Register(name='xer_ca', size=1),
        Register(name='xer_bc', size=1),
        Register(name='cr0_321', size=1),
        Register(name='cr0_0', size=1, alias_names=('cr0',)),
        Register(name='cr1_321', size=1),
        Register(name='cr1_0', size=1, alias_names=('cr1',)),
        Register(name='cr2_321', size=1),
        Register(name='cr2_0', size=1, alias_names=('cr2',)),
        Register(name='cr3_321', size=1),
        Register(name='cr3_0', size=1, alias_names=('cr3',)),
        Register(name='cr4_321', size=1),
        Register(name='cr4_0', size=1, alias_names=('cr4',)),
        Register(name='cr5_321', size=1),
        Register(name='cr5_0', size=1, alias_names=('cr5',)),
        Register(name='cr6_321', size=1),
        Register(name='cr6_0', size=1, alias_names=('cr6',)),
        Register(name='cr7_321', size=1),
        Register(name='cr7_0', size=1, alias_names=('cr7',)),
        Register(name='fpround', size=1, floating_point=True),
        Register(name='dfpround', size=1, floating_point=True),
        Register(name='c_fpcc', size=1, floating_point=True),
        Register(name='vrsave', size=4, vector=True),
        Register(name='vscr', size=4, vector=True),
        Register(name='emnote', size=4),
        Register(name='cmstart', size=8),
        Register(name='cmlen', size=8),
        Register(name='nraddr', size=8),
        Register(name='nraddr_gpr2', size=8),
        Register(name='redir_sp', size=8),
        Register(name='redir_stack', size=256),
        Register(name='ip_at_syscall', size=8, artificial=True),
        Register(name='sprg3_ro', size=8),
        Register(name='tfhar', size=8),
        Register(name='texasr', size=8),
        Register(name='tfiar', size=8),
        Register(name='ppr', size=8),
        Register(name='texasru', size=4),
        Register(name='pspb', size=4),
    ]

    function_prologs = {
        br"[\x00-\xff]{2}\x21\x94\xa6\x02\x08\x7c",                        # stwu r1, -off(r1); mflr r0
    }
    function_epilogs = {
        br"\xa6\x03[\x00-\xff]{2}([\x00-\xff]{4}){0,6}\x20\x00\x80\x4e"    # mtlr reg; ... ; blr
    }

    got_section_name = '.plt'
    ld_linux_name = 'ld64.so.1'
    elf_tls = TLSArchInfo(1, 92, [], [84], [], 0x7000, 0x8000)


register_arch([r'.*p\w*pc.*be'], 64, 'Iend_BE', ArchPPC64)
register_arch([r'.*p\w*pc.*'], 64, 'any', ArchPPC64)
