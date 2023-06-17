import ctypes as ct
from struct import unpack
import enum


class State(enum.Enum):
    PreRun = 1
    Running = 2
    Breakpoint = 3


class StackFrame():
    def __init__(self, bin_code_line, txt_code_line, func_scope_obj):
        self.bin_code_line = bin_code_line
        self.txt_code_line = txt_code_line
        self.func_scope_obj = func_scope_obj
        self.variables = {}


class StackFrameVariable():
    def __init__(self, id, name, addr, variable_obj, variable_type=None):
        self.id = id
        self.name = name
        self.addr = addr
        self.variable_obj = variable_obj  # Param/Reg object
        # self.variable_type = variable_type  # Fields type / Single Field type


class Func():
    def __init__(self, bin_start_line, name, bin_end_line=None, txt_start_line=None, txt_end_line=None,
                 args_addresses=None):
        self.name = name
        self.bin_start_line = bin_start_line
        self.bin_end_line = bin_end_line
        self.txt_start_line = txt_start_line
        self.txt_end_line = txt_end_line
        if args_addresses:
            self.args_addresses = [DebuggerUtils.get_abs_addr_from_str(addr) for addr in args_addresses if
                                   addr is not None]
        else:
            self.args_addresses = []

    def set_additional_data(self, bin_end_line=None, txt_start_line=None, txt_end_line=None, args_addresses=None):
        if bin_end_line:
            self.bin_end_line = bin_end_line
        if txt_start_line:
            self.txt_start_line = txt_start_line
        if txt_end_line:
            self.txt_end_line = txt_end_line
        if args_addresses:
            self.args_addresses = args_addresses
        else:
            self.args_addresses = []


class DebuggerUtils:
    #The value of a return opcode in decimal
    ReturnOP = 274877906948
    SEQ_PARAM_MEM = 0x0
    RX_MEMORY = 0x0

    @staticmethod
    def bin_file_to_shorts_list(bin_file_path):
        with open(bin_file_path, 'rb') as binary_file:
            arr = bytearray(binary_file.read())
            file_length_in_shorts = (len(arr) // 2)
            ushorts_list = list(unpack('H' * file_length_in_shorts, arr))
            data = (ct.c_ushort * file_length_in_shorts)()
            # for i in range(file_length_in_shorts):
            #     data[i] = ct.c_ushort(tuple_of_ushorts[i])
            return ushorts_list
            

    @staticmethod
    def get_u_shorts_array(num):
        arr = num.to_bytes(8, 'little')
        file_length_in_shorts = (len(arr) // 2)
        data = (ct.c_ushort * file_length_in_shorts)()
        tuple_of_ushorts = unpack('H' * file_length_in_shorts, arr)
        for i in range(file_length_in_shorts):
            data[i] = ct.c_ushort(tuple_of_ushorts[i])
        return data

    @staticmethod
    def get_num_from_u_shorts_array(arr):
        b = bytes(arr)
        num = int.from_bytes(b, 'little')
        return num

    @staticmethod
    def select_bits_from_num(num, start_bit, end_bit):
        binary_string = bin(num)[2:]
        binary_string = binary_string[::-1]
        padding_zeroes = (41 - len(binary_string)) * "0"
        binary_string = binary_string + padding_zeroes
        return int(binary_string[start_bit:end_bit][::-1], 2)

    @staticmethod
    def get_u_shorts_array_from_list(lst):
        arr_len = len(lst)
        arr = (ct.c_ushort * arr_len)()
        for i in range(arr_len):
            arr[i] = ct.c_ushort(lst[i])
        return arr

    @staticmethod
    def get_binary(bits_position_value_dict):  # for example : {"0:3":4, "4:19":24, "37:37":1}
        binary = 0
        for key in sorted(bits_position_value_dict.keys(), key=lambda t: int(t.split(':')[0])):
            start = int(key.split(':')[0])
            end = int(key.split(':')[1])
            value_bit_size = end - start + 1

            value = int(bits_position_value_dict[key])
            if len(bin(value)[2:]) > value_bit_size:
                raise Exception("Value is bigger than bits allocated for this")

            shifted_value = value << start
            binary |= shifted_value
        return binary

    @staticmethod
    def get_jump_opcode(to_code_line, push_curr_address=False):
        bits_values_pos = {"0:3": 4, "4:19": to_code_line, "37:37": int(push_curr_address)}
        jump_opcode = DebuggerUtils.get_binary(bits_values_pos)
        data = DebuggerUtils.get_u_shorts_array(jump_opcode)
        return data

    @staticmethod
    def op_is_branch(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        first_opcode_bits = DebuggerUtils.select_bits_from_num(opcode_as_num, 0, 4)
        return (first_opcode_bits == 4 or first_opcode_bits == 0xB)

    @staticmethod
    def op_is_cond_branch(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        is_branch = DebuggerUtils.op_is_branch(opcode)
        return is_branch and (DebuggerUtils.select_bits_from_num(opcode_as_num, 36, 37) == 1)

    @staticmethod
    def op_is_jump(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        is_branch = DebuggerUtils.op_is_branch(opcode)
        op_is_conditional_branch = DebuggerUtils.op_is_cond_branch(opcode)
        return is_branch and not op_is_conditional_branch and (DebuggerUtils.select_bits_from_num(opcode_as_num, 37, 38) == 0)

    @staticmethod
    def op_is_return(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        return opcode_as_num == DebuggerUtils.ReturnOP

    @staticmethod
    def op_is_write(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        first_opcode_bits = DebuggerUtils.select_bits_from_num(opcode_as_num, 0, 4)
        return (first_opcode_bits == 0 or first_opcode_bits == 9)

    @staticmethod
    def op_is_copy(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        first_opcode_bits = DebuggerUtils.select_bits_from_num(opcode_as_num, 0, 4)
        return (first_opcode_bits == 1 or first_opcode_bits == 0xA)

    @staticmethod
    def op_is_add_base_to_dest_write(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        add_base_to_dest_flag = DebuggerUtils.select_bits_from_num(opcode_as_num, 6, 7) == 1
        config_dest_type = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 6) == 0
        return DebuggerUtils.op_is_write(opcode) and add_base_to_dest_flag and config_dest_type

    @staticmethod
    def op_is_add_base_to_dest_copy(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        add_base_to_dest_flag = DebuggerUtils.select_bits_from_num(opcode_as_num, 6, 7) == 1
        config_dest_type = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 6) == 0
        return DebuggerUtils.op_is_copy(opcode) and add_base_to_dest_flag and config_dest_type

    @staticmethod
    def get_dest_addr_from_copy_or_write(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        dest = DebuggerUtils.select_bits_from_num(opcode_as_num, 7, 22)
        dest_type = DebuggerUtils.select_bits_from_num(opcode_as_num, 4, 6)

        if dest_type == 0:
            return dest
        elif dest_type == 1:
            return DebuggerUtils.SEQ_PARAM_MEM + dest
        else:  # 2
            return DebuggerUtils.RX_MEMORY + dest

    @staticmethod
    def get_data_from_write(opcode):
        opcode_as_num = DebuggerUtils.get_num_from_u_shorts_array(opcode)
        data = DebuggerUtils.select_bits_from_num(opcode_as_num, 23, 39)
        return data

    @staticmethod
    def is_breakpoint_legal_on_opcode(opcode):
        legal = True
        op_is_ret = DebuggerUtils.op_is_return(opcode)
        op_is_jump = DebuggerUtils.op_is_jump(opcode)

        if op_is_ret or op_is_jump:
            legal = False

        return legal

    @staticmethod
    def get_abs_addr_from_str(st):
        if ':' in st:
            base, offset = st.split(':')
            if base == '0':
                base = 0
            elif base == '1':
                base = DebuggerUtils.SEQ_PARAM_MEM
            else:
                base = DebuggerUtils.RX_MEMORY

            offset = int(offset, 16)
            addr = base + offset
        else:
            addr = int(st, 16)
        return addr

    # id() function is not intended to be de referenceable
    # will work only if CPython implementation
    # Warning - if object is not there - undefined behavior
    @staticmethod
    def get_py_obj_by_id(obj_id):
        return ct.cast(obj_id, ct.py_object).value


class Breakpoint():
    # original_opcode  = The opcode that the breakpoint is stopping at
    def __init__(self, code_bin_line, original_opcode):
        self.code_bin_line = code_bin_line
        self.original_opcode = original_opcode
