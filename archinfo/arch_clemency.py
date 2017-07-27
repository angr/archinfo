from .arch import Arch, register_arch

class ArchClemency(Arch):
    def __init__(self):
        # TODO: "Iend_LE" is wrong
        super(ArchMSP430, self).__init__("Iend_LE")
        # TODO: Define function prologs
        self.qemu_name = 'clemency'
        self.bits = 27
        self.name = "Clemency"
        self.ida_processor = 'clemency'
        self.max_inst_bytes = 6
        # ip_offset = 136
        # sp_offset = 124
        # bp_offset = 128
        # ret_offset = 16
        # lr_offset = 132
        # syscall_num_offset = 16
        # call_pushes_ret = False
        # stack_change = -4
        # branch_delay_slot = True
        self.sizeof = {'short': 16, 'int': 16, 'long': 32, 'long long': 64}
    function_prologs = {}
    function_epilogs = {}

    ret_instruction = ""
    nop_instruction = ""
    # instruction_alignment = 4
    persistent_regs = []

    default_register_values = [
        ( 'sp', Arch.initial_sp, True, 'global' ),   # the stack
    ]
    entry_register_values = {
    }

    default_symbolic_registers = []

    register_names = {(3*x) : 'r' + str(x) for x in range(32)}
    register_names[3 * 31] = 'pc'
    register_names[3 * 30] = 'ra'
    register_names[3 * 29] = 'st'

    registers = {(3*x, 3) : 'r' + str(x) for x in range(32)}
    registers['pc'] = (3 * 31, 3)
    registers['ra'] = (3 * 30, 3)
    registers['st'] = (3 * 29, 3)

    argument_registers = {registers['r' + str(x)][0] for x in range(9)}

    # EDG: Can you even use PIC here? I don't think so
    dynamic_tag_translation = {}

register_arch([r'clemency'], 32, 'Iend_LE' , ArchClemency)
