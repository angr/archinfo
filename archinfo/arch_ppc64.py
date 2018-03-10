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

from .arch import Arch, register_arch, Endness
from .tls import TLSArchInfo

# Note: PowerPC doesn't have pc, so guest_CIA is commented as IP (no arch visible register)
# Normally r1 is used as stack pointer

class ArchPPC64(Arch):
    def __init__(self, endness=Endness.LE):
        super(ArchPPC64, self).__init__(endness)
        if endness == Endness.BE:
            self.function_prologs = {
                r"\x94\x21[\x00-\xff]{2}\x7c\x08\x02\xa6",                        # stwu r1, -off(r1); mflr r0
                r"(?!\x94\x21[\x00-\xff]{2})\x7c\x08\x02\xa6",                    # mflr r0
                r"\xf8\x61[\x00-\xff]{2}",                                        # std r3, -off(r1)
            }
            self.function_epilogs = {
                r"[\x00-\xff]{2}\x03\xa6([\x00-\xff]{4}){0,6}\x4e\x80\x00\x20"    # mtlr reg; ... ; blr
            }
            self.triplet = 'powerpc-linux-gnu'

    bits = 64
    vex_arch = "VexArchPPC64"
    name = "PPC64"
    qemu_name = 'ppc64'
    ida_processor = 'ppc64'
    triplet = 'powerpc64le-linux-gnu'
    linux_name = 'ppc750'
    max_inst_bytes = 4
    ip_offset = 1296
    sp_offset = 24
    bp_offset = 264
    ret_offset = 40
    lr_offset = 1304
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
    persistent_regs = [ 'r2' ]

    function_prologs = {
        r"[\x00-\xff]{2}\x21\x94\xa6\x02\x08\x7c",                        # stwu r1, -off(r1); mflr r0
    }
    function_epilogs = {
        r"\xa6\x03[\x00-\xff]{2}([\x00-\xff]{4}){0,6}\x20\x00\x80\x4e"    # mtlr reg; ... ; blr
    }

    default_register_values = [
        ( 'sp', initial_sp, True, 'global' ) # the stack
    ]
    entry_register_values = {
        'r2': 'toc',
        'r3': 'argc',
        'r4': 'argv',
        'r5': 'envp',
        'r6': 'auxv',
        'r7': 'ld_destructor'
    }

    default_symbolic_registers = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12',
                                   'r13', 'r14', 'r15', 'r16', 'r17', 'r18', 'r19', 'r20', 'r21', 'r22', 'r23', 'r24',
                                   'r25', 'r26', 'r27', 'r28', 'r29', 'r30', 'r31', 'sp', 'pc']

    register_names = {
        16: 'r0',
        24: 'r1',
        32: 'r2',
        40: 'r3',
        48: 'r4',
        56: 'r5',
        64: 'r6',
        72: 'r7',
        80: 'r8',
        88: 'r9',
        96: 'r10',
        104: 'r11',
        112: 'r12',
        120: 'r13',
        128: 'r14',
        136: 'r15',
        144: 'r16',
        152: 'r17',
        160: 'r18',
        168: 'r19',
        176: 'r20',
        184: 'r21',
        192: 'r22',
        200: 'r23',
        208: 'r24',
        216: 'r25',
        224: 'r26',
        232: 'r27',
        240: 'r28',
        248: 'r29',
        256: 'r30',
        264: 'r31',
        272: 'v0',
        288: 'v1',
        304: 'v2',
        320: 'v3',
        336: 'v4',
        352: 'v5',
        368: 'v6',
        384: 'v7',
        400: 'v8',
        416: 'v9',
        432: 'v10',
        448: 'v11',
        464: 'v12',
        480: 'v13',
        496: 'v14',
        512: 'v15',
        528: 'v16',
        544: 'v17',
        560: 'v18',
        576: 'v19',
        592: 'v20',
        608: 'v21',
        624: 'v22',
        640: 'v23',
        656: 'v24',
        672: 'v25',
        688: 'v26',
        704: 'v27',
        720: 'v28',
        736: 'v29',
        752: 'v30',
        768: 'v31',
        784: 'v32',
        800: 'v33',
        816: 'v34',
        832: 'v35',
        848: 'v36',
        864: 'v37',
        880: 'v38',
        896: 'v39',
        912: 'v40',
        928: 'v41',
        944: 'v42',
        960: 'v43',
        976: 'v44',
        992: 'v45',
        1008: 'v46',
        1024: 'v47',
        1040: 'v48',
        1056: 'v49',
        1072: 'v50',
        1088: 'v51',
        1104: 'v52',
        1120: 'v53',
        1136: 'v54',
        1152: 'v55',
        1168: 'v56',
        1184: 'v57',
        1200: 'v58',
        1216: 'v59',
        1232: 'v60',
        1248: 'v61',
        1264: 'v62',
        1280: 'v63',
        1296: 'pc',
        1304: 'lr',
        1312: 'ctr',
        1320: 'xer_so',
        1321: 'xer_ov',
        1322: 'xer_ca',
        1323: 'xer_bc',
        1324: 'cr0_321',
        1325: 'cr0_0',
        1326: 'cr1_321',
        1327: 'cr1_0',
        1328: 'cr2_321',
        1329: 'cr2_0',
        1330: 'cr3_321',
        1331: 'cr3_0',
        1332: 'cr4_321',
        1333: 'cr4_0',
        1334: 'cr5_321',
        1335: 'cr5_0',
        1336: 'cr6_321',
        1337: 'cr6_0',
        1338: 'cr7_321',
        1339: 'cr7_0',
        1340: 'fpround',
        1341: 'dfpround',
        1344: 'vrsave',
        1348: 'vscr',
        1352: 'emnote',
        1360: 'cmstart',
        1368: 'cmlen',
        1376: 'nraddr',
        1384: 'nraddr_gpr2',
        1392: 'redir_sp',
        1400: 'redir_stack',
        1656: 'ip_at_syscall',
        1664: 'sprg3_ro',
        1672: 'tfhar',
        1680: 'texasr',
        1688: 'tfiar',
        1704: 'texasru',
    }

    registers = {
        'gpr0': (16, 8),
        'r0': (16, 8),
        'gpr1': (24, 8),
        'r1': (24, 8),
        'sp': (24, 8),
        'gpr2': (32, 8),
        'r2': (32, 8),
        'rtoc': (32, 8),
        'gpr3': (40, 8),
        'r3': (40, 8),
        'gpr4': (48, 8),
        'r4': (48, 8),
        'gpr5': (56, 8),
        'r5': (56, 8),
        'gpr6': (64, 8),
        'r6': (64, 8),
        'gpr7': (72, 8),
        'r7': (72, 8),
        'gpr8': (80, 8),
        'r8': (80, 8),
        'gpr9': (88, 8),
        'r9': (88, 8),
        'gpr10': (96, 8),
        'r10': (96, 8),
        'gpr11': (104, 8),
        'r11': (104, 8),
        'gpr12': (112, 8),
        'r12': (112, 8),
        'gpr13': (120, 8),
        'r13': (120, 8),
        'gpr14': (128, 8),
        'r14': (128, 8),
        'bp': (136, 8),
        'gpr15': (136, 8),
        'r15': (136, 8),
        'gpr16': (144, 8),
        'r16': (144, 8),
        'gpr17': (152, 8),
        'r17': (152, 8),
        'gpr18': (160, 8),
        'r18': (160, 8),
        'gpr19': (168, 8),
        'r19': (168, 8),
        'gpr20': (176, 8),
        'r20': (176, 8),
        'gpr21': (184, 8),
        'r21': (184, 8),
        'gpr22': (192, 8),
        'r22': (192, 8),
        'gpr23': (200, 8),
        'r23': (200, 8),
        'gpr24': (208, 8),
        'r24': (208, 8),
        'gpr25': (216, 8),
        'r25': (216, 8),
        'gpr26': (224, 8),
        'r26': (224, 8),
        'gpr27': (232, 8),
        'r27': (232, 8),
        'gpr28': (240, 8),
        'r28': (240, 8),
        'gpr29': (248, 8),
        'r29': (248, 8),
        'gpr30': (256, 8),
        'r30': (256, 8),
        'gpr31': (264, 8),
        'r31': (264, 8),
        'v0': (272, 16),
        'vsr0': (272, 16),
        'v1': (288, 16),
        'vsr1': (288, 16),
        'v2': (304, 16),
        'vsr2': (304, 16),
        'v3': (320, 16),
        'vsr3': (320, 16),
        'v4': (336, 16),
        'vsr4': (336, 16),
        'v5': (352, 16),
        'vsr5': (352, 16),
        'v6': (368, 16),
        'vsr6': (368, 16),
        'v7': (384, 16),
        'vsr7': (384, 16),
        'v8': (400, 16),
        'vsr8': (400, 16),
        'v9': (416, 16),
        'vsr9': (416, 16),
        'v10': (432, 16),
        'vsr10': (432, 16),
        'v11': (448, 16),
        'vsr11': (448, 16),
        'v12': (464, 16),
        'vsr12': (464, 16),
        'v13': (480, 16),
        'vsr13': (480, 16),
        'v14': (496, 16),
        'vsr14': (496, 16),
        'v15': (512, 16),
        'vsr15': (512, 16),
        'v16': (528, 16),
        'vsr16': (528, 16),
        'v17': (544, 16),
        'vsr17': (544, 16),
        'v18': (560, 16),
        'vsr18': (560, 16),
        'v19': (576, 16),
        'vsr19': (576, 16),
        'v20': (592, 16),
        'vsr20': (592, 16),
        'v21': (608, 16),
        'vsr21': (608, 16),
        'v22': (624, 16),
        'vsr22': (624, 16),
        'v23': (640, 16),
        'vsr23': (640, 16),
        'v24': (656, 16),
        'vsr24': (656, 16),
        'v25': (672, 16),
        'vsr25': (672, 16),
        'v26': (688, 16),
        'vsr26': (688, 16),
        'v27': (704, 16),
        'vsr27': (704, 16),
        'v28': (720, 16),
        'vsr28': (720, 16),
        'v29': (736, 16),
        'vsr29': (736, 16),
        'v30': (752, 16),
        'vsr30': (752, 16),
        'v31': (768, 16),
        'vsr31': (768, 16),
        'v32': (784, 16),
        'vsr32': (784, 16),
        'v33': (800, 16),
        'vsr33': (800, 16),
        'v34': (816, 16),
        'vsr34': (816, 16),
        'v35': (832, 16),
        'vsr35': (832, 16),
        'v36': (848, 16),
        'vsr36': (848, 16),
        'v37': (864, 16),
        'vsr37': (864, 16),
        'v38': (880, 16),
        'vsr38': (880, 16),
        'v39': (896, 16),
        'vsr39': (896, 16),
        'v40': (912, 16),
        'vsr40': (912, 16),
        'v41': (928, 16),
        'vsr41': (928, 16),
        'v42': (944, 16),
        'vsr42': (944, 16),
        'v43': (960, 16),
        'vsr43': (960, 16),
        'v44': (976, 16),
        'vsr44': (976, 16),
        'v45': (992, 16),
        'vsr45': (992, 16),
        'v46': (1008, 16),
        'vsr46': (1008, 16),
        'v47': (1024, 16),
        'vsr47': (1024, 16),
        'v48': (1040, 16),
        'vsr48': (1040, 16),
        'v49': (1056, 16),
        'vsr49': (1056, 16),
        'v50': (1072, 16),
        'vsr50': (1072, 16),
        'v51': (1088, 16),
        'vsr51': (1088, 16),
        'v52': (1104, 16),
        'vsr52': (1104, 16),
        'v53': (1120, 16),
        'vsr53': (1120, 16),
        'v54': (1136, 16),
        'vsr54': (1136, 16),
        'v55': (1152, 16),
        'vsr55': (1152, 16),
        'v56': (1168, 16),
        'vsr56': (1168, 16),
        'v57': (1184, 16),
        'vsr57': (1184, 16),
        'v58': (1200, 16),
        'vsr58': (1200, 16),
        'v59': (1216, 16),
        'vsr59': (1216, 16),
        'v60': (1232, 16),
        'vsr60': (1232, 16),
        'v61': (1248, 16),
        'vsr61': (1248, 16),
        'v62': (1264, 16),
        'vsr62': (1264, 16),
        'v63': (1280, 16),
        'vsr63': (1280, 16),
        'cia': (1296, 8),
        'ip': (1296, 8),
        'pc': (1296, 8),
        'lr': (1304, 8),
        'ctr': (1312, 8),
        'xer_so': (1320, 1),
        'xer_ov': (1321, 1),
        'xer_ca': (1322, 1),
        'xer_bc': (1323, 1),
        'cr0_321': (1324, 1),
        'cr0': (1325, 1),
        'cr0_0': (1325, 1),
        'cr1_321': (1326, 1),
        'cr1': (1327, 1),
        'cr1_0': (1327, 1),
        'cr2_321': (1328, 1),
        'cr2': (1329, 1),
        'cr2_0': (1329, 1),
        'cr3_321': (1330, 1),
        'cr3': (1331, 1),
        'cr3_0': (1331, 1),
        'cr4_321': (1332, 1),
        'cr4': (1333, 1),
        'cr4_0': (1333, 1),
        'cr5_321': (1334, 1),
        'cr5': (1335, 1),
        'cr5_0': (1335, 1),
        'cr6_321': (1336, 1),
        'cr6': (1337, 1),
        'cr6_0': (1337, 1),
        'cr7_321': (1338, 1),
        'cr7': (1339, 1),
        'cr7_0': (1339, 1),
        'fpround': (1340, 1),
        'dfpround': (1341, 1),
        'vrsave': (1344, 4),
        'vscr': (1348, 4),
        'emnote': (1352, 4),
        'cmstart': (1360, 8),
        'cmlen': (1368, 8),
        'nraddr': (1376, 8),
        'nraddr_gpr2': (1384, 8),
        'redir_sp': (1392, 8),
        'redir_stack': (1400, 256),
        'ip_at_syscall': (1656, 8),
        'sprg3_ro': (1664, 8),
        'tfhar': (1672, 8),
        'texasr': (1680, 8),
        'tfiar': (1688, 8),
        'texasru': (1704, 4),
    }

    argument_registers = {
        registers['r3'][0],
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
        registers['r10'][0]
    }

    argument_register_positions = {
        registers['r3'][0]: 0,
        registers['r4'][0]: 1,
        registers['r5'][0]: 2,
        registers['r6'][0]: 3,
        registers['r7'][0]: 4,
        registers['r8'][0]: 5,
        registers['r9'][0]: 6,
        registers['r10'][0]: 7,
        # fp registers
        registers['vsr1'][0]: 0,
        registers['vsr2'][0]: 1,
        registers['vsr3'][0]: 2,
        registers['vsr4'][0]: 3,
        registers['vsr5'][0]: 4,
        registers['vsr6'][0]: 5,
        registers['vsr7'][0]: 6,
        registers['vsr8'][0]: 7,
        registers['vsr9'][0]: 8,
        registers['vsr10'][0]: 9,
        registers['vsr11'][0]: 10,
        registers['vsr12'][0]: 11,
        registers['vsr13'][0]: 12,
        # vector registers
        registers['vsr2'][0]: 0,
        registers['vsr3'][0]: 1,
        registers['vsr4'][0]: 2,
        registers['vsr5'][0]: 3,
        registers['vsr6'][0]: 4,
        registers['vsr7'][0]: 5,
        registers['vsr8'][0]: 6,
        registers['vsr9'][0]: 7,
        registers['vsr10'][0]: 8,
        registers['vsr11'][0]: 9,
        registers['vsr12'][0]: 10,
        registers['vsr13'][0]: 11,
    }
    
    got_section_name = '.plt'
    ld_linux_name = 'ld64.so.1'
    elf_tls = TLSArchInfo(1, 92, [], [84], [], 0x7000, 0x8000)


register_arch([r'.*p\w*pc.*be'], 64, 'Iend_BE', ArchPPC64)
register_arch([r'.*p\w*pc.*'], 64, 'any', ArchPPC64)
