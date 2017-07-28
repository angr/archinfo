
from .arch import Arch, register_arch


class ArchClemency(Arch):
    """
    The awesome architecture created by LegitBS for DEF CON CTF 2017 Finals.

    Each byte is 9 bits long.
    """

    def __init__(self, endness="Iend_ME"):
        super(ArchClemency, self).__init__("Iend_ME")
        # TODO: Define function prologs
        self.qemu_name = 'clemency'
        self.bits = 27
        self.name = "clemency"
        self.ida_processor = 'clemency'
        self.max_inst_bytes = 6
        ip_offset = 93
        sp_offset = 87
        bp_offset = None  # there is no bp in cLEMENCy
        ret_offset = None
        lr_offset = 90
        syscall_num_offset = None
        call_pushes_ret = False
        stack_change = -3
        branch_delay_slot = False
        self.sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}

    function_prologs = { }
    function_epilogs = { }

    ret_instruction = ""
    nop_instruction = ""
    # instruction_alignment = 4
    persistent_regs = [ ]

    default_symbolic_registers = [ ]

    register_names = {
        0 : 'r0',
        3 * 1: 'r1',
        3 * 2: 'r2',
        3 * 3: 'r3',
        3 * 4: 'r4',
        3 * 5: 'r5',
        3 * 6: 'r6',
        3 * 7: 'r7',
        3 * 8: 'r8',
        3 * 9: 'r9',
        3 * 10: 'r10',
        3 * 11: 'r11',
        3 * 12: 'r12',
        3 * 13: 'r13',
        3 * 14: 'r14',
        3 * 15: 'r15',
        3 * 16: 'r16',
        3 * 17: 'r17',
        3 * 18: 'r18',
        3 * 19: 'r19',
        3 * 20: 'r20',
        3 * 21: 'r21',
        3 * 22: 'r22',
        3 * 23: 'r23',
        3 * 24: 'r24',
        3 * 25: 'r25',
        3 * 26: 'r26',
        3 * 27: 'r27',
        3 * 28: 'r28',
        3 * 29: 'r29',
    }
    register_names[3 * 31] = 'pc'
    register_names[3 * 31] = 'ip'
    register_names[3 * 30] = 'ra'
    register_names[3 * 29] = 'sp'
    register_names[3 * 41] = 'sf'
    register_names[3 * 42] = 'of'
    register_names[3 * 43] = 'cf'
    register_names[3 * 44] = 'zf'

    registers = dict(('r' + str(x), (3*x, 3)) for x in range(32))
    registers['pc'] = (3 * 31, 3)
    registers['ip'] = (3 * 31, 3)
    registers['ra'] = (3 * 30, 3)
    registers['st'] = (3 * 29, 3)
    registers['sp'] = (3 * 29, 3)
    # Data Sent Interrupt Enabled: 3 * 32
    # Data Received Interrupt Enabled: 3 * 33
    # Memory Exception Enabled: 3 * 34
    # Divide by 0 Exception Enabled: 3 * 35
    # Invalid Instruction Exception Enabled: 3 * 36
    # Timer4 Interrupt Enabled: 3 * 37
    # Timer3 Interrupt Enabled: 3 * 38
    # Timer2 Interrupt Enabled: 3 * 39
    # Timer1 Interrupt Enabled: 3 * 40
    registers['sf'] = (3 * 41, 3)
    registers['of'] = (3 * 42, 3)
    registers['cf'] = (3 * 43, 3)
    registers['zf'] = (3 * 44, 3)

    default_register_values = [
        ( 'sp', 0x3fffc00, True, 'global' ),     # the stack
    ]
    entry_register_values = { 'r%d'%r: 0 for r in range(29) }
    entry_register_values['sp'] = 0
    entry_register_values['ra'] = 0

    argument_registers = {
        registers['r0'][0],
        registers['r1'][0],
        registers['r2'][0],
        registers['r3'][0],
        registers['r4'][0],
        registers['r5'][0],
        registers['r6'][0],
        registers['r7'][0],
        registers['r8'][0],
        registers['r9'][0],
    }

    # EDG: Can you even use PIC here? I don't think so
    dynamic_tag_translation = {}


register_arch([r'clemency'], 32, 'Iend_LE' , ArchClemency)
